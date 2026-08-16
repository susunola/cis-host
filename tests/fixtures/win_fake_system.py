"""In-memory fake for the Windows OS boundary that ohbs_engine.ps1's
Invoke-Check/Invoke-Fix call through: the registry (Get-ItemProperty/
Set-ItemProperty/Test-Path/New-Item), secedit (security policy +
user rights export/import), auditpol (advanced audit policy), and
Windows Firewall (Get-NetFirewallProfile/Set-NetFirewallProfile).

Unlike the Linux FakeSystem (tests/fixtures/fake_system.py), which
patches Python module-level function bindings via importlib, this
fake is implemented as a block of PowerShell function definitions
that get dot-sourced *before* ohbs_engine.ps1 itself is dot-sourced.
PowerShell resolves a locally-defined function over a same-named
cmdlet/external command, so once these are defined, ohbs_engine.py's
calls to Get-ItemProperty/secedit/auditpol/Get-NetFirewallProfile
resolve to these fakes instead of touching a real Windows host -- the
same "patch the boundary, keep the real check/fix logic" approach as
the Linux harness, adapted to PowerShell's dispatch rules instead of
Python's module globals.

See harness.py for the driver that emits a full PowerShell script
(this fake + ohbs_engine.ps1, dot-sourced + one Invoke-Check/Invoke-Fix
call per step) and shells out to `pwsh` to run it.
"""

FAKE_WINDOWS_SYSTEM_PS1 = r"""
# ---- in-memory registry -------------------------------------------------
$Global:FakeReg = @{}

function Get-ItemProperty {
    param($Path, $Name, [switch]$ErrorAction)
    $key = "$Path|$Name"
    if ($Global:FakeReg.ContainsKey($key)) {
        return [PSCustomObject]@{ $Name = $Global:FakeReg[$key] }
    }
    throw "FakeWindowsSystem: registry value not found: $key"
}

function Set-ItemProperty {
    param($Path, $Name, $Value, $Type, [switch]$Force)
    $Global:FakeReg["$Path|$Name"] = $Value
}

function Test-Path {
    param($Path)
    # ohbs_engine.ps1 only calls Test-Path on registry paths (to decide
    # whether New-Item is needed before Set-ItemProperty) and on secedit
    # temp files it just wrote itself via the real filesystem -- so it is
    # safe to always report "exists" for registry-like paths and defer
    # to the real Test-Path for everything else (temp .inf files).
    if ("$Path".StartsWith("HK")) { return $true }
    return (Microsoft.PowerShell.Management\Test-Path $Path)
}

function New-Item {
    param($Path, [switch]$Force)
    if ("$Path".StartsWith("HK")) { return }
    Microsoft.PowerShell.Management\New-Item -Path $Path -Force:$Force | Out-Null
}

# ---- secedit (security policy / user rights via .inf export/import) ----
# $Global:FakeSecPol / $Global:FakeUserRights are seeded by the test
# driver before Invoke-Check/Invoke-Fix run.
$Global:FakeSecPol = @{}
$Global:FakeUserRights = @{}

function secedit {
    $verb = $args[0]
    $cfgIdx = [array]::IndexOf($args, "/cfg")
    $areasIdx = [array]::IndexOf($args, "/areas")
    $cfgPath = if ($cfgIdx -ge 0) { $args[$cfgIdx + 1] } else { $null }
    $area = if ($areasIdx -ge 0) { $args[$areasIdx + 1] } else { $null }

    if ($verb -eq "/export") {
        $lines = @("[Unicode]", "Unicode=yes", "[System Access]")
        if ($area -eq "SECURITYPOLICY") {
            foreach ($k in $Global:FakeSecPol.Keys) {
                $lines += "$k = $($Global:FakeSecPol[$k])"
            }
        } elseif ($area -eq "USER_RIGHTS") {
            $lines += "[Privilege Rights]"
            foreach ($k in $Global:FakeUserRights.Keys) {
                $lines += "$k = $($Global:FakeUserRights[$k])"
            }
        }
        Microsoft.PowerShell.Management\Set-Content -Path $cfgPath -Value ($lines -join "`r`n")
        return
    }
    if ($verb -eq "/configure") {
        $dbIdx = [array]::IndexOf($args, "/db")
        # find the /cfg arg for /configure (re-derive since $cfgIdx above
        # matched the same flag name in a differently-ordered arg list)
        $cfgIdx2 = [array]::IndexOf($args, "/cfg")
        $cfgPath2 = $args[$cfgIdx2 + 1]
        # ohbs_engine.ps1's own fix code writes the *updated* .inf via
        # [System.IO.File]::WriteAllText($tmp2, $c) (see user-right's
        # Invoke-Fix), not Set-Content/Out-File -- and on a posix pwsh
        # host, .NET's File APIs treat a Windows-style "dir\file.inf"
        # path as one literal filename (no directory component) while
        # PowerShell's own Get-Content/Set-Content treat the backslash
        # as a path separator. Those are two different physical files
        # on disk here. So this read must use [System.IO.File]::
        # ReadAllText (matching WriteAllText's own path semantics)
        # rather than Get-Content, or it would see stale/pre-fix
        # content written by this fake's own /export branch above.
        $content = [System.IO.File]::ReadAllText($cfgPath2)
        foreach ($ln in ($content -split "`r`n")) {
            if ($ln -match "^\s*([^=\[\]][^=]*?)\s*=\s*(.+)$") {
                $k = $Matches[1].Trim(); $v = $Matches[2].Trim()
                if ($area -eq "USER_RIGHTS" -or $Global:FakeUserRights.ContainsKey($k)) {
                    $Global:FakeUserRights[$k] = $v
                } else {
                    $Global:FakeSecPol[$k] = $v
                }
            }
        }
        $Global:LASTEXITCODE = 0
        return
    }
}

# ---- auditpol (advanced audit policy) -----------------------------------
$Global:FakeAuditPol = @{}

function auditpol {
    if ($args[0] -eq "/get") {
        $subArg = ($args | Where-Object { $_ -like "/subcategory:*" })
        $sub = ($subArg -replace '^/subcategory:', '').Trim('"')
        $state = $Global:FakeAuditPol[$sub]
        if (-not $state) { $state = "No Auditing" }
        return "  $sub                                  $state"
    }
    if ($args[0] -eq "/set") {
        $subArg = ($args | Where-Object { $_ -like "/subcategory:*" })
        $sub = ($subArg -replace '^/subcategory:', '').Trim('"')
        $successArg = ($args | Where-Object { $_ -like "/success:*" })
        $failureArg = ($args | Where-Object { $_ -like "/failure:*" })
        $succ = if ($successArg) { $successArg -replace '/success:', '' } else { $null }
        $fail = if ($failureArg) { $failureArg -replace '/failure:', '' } else { $null }
        $prevState = $Global:FakeAuditPol[$sub]
        $prevSucc = ($prevState -like "*Success*")
        $prevFail = ($prevState -like "*Failure*")
        $newSucc = if ($succ -eq "enable") { $true } elseif ($succ -eq "disable") { $false } else { $prevSucc }
        $newFail = if ($fail -eq "enable") { $true } elseif ($fail -eq "disable") { $false } else { $prevFail }
        $Global:FakeAuditPol[$sub] =
            if ($newSucc -and $newFail) { "Success and Failure" }
            elseif ($newSucc) { "Success" }
            elseif ($newFail) { "Failure" }
            else { "No Auditing" }
    }
}

# ---- Windows Firewall ----------------------------------------------------
$Global:FakeFirewall = @{}

function Get-NetFirewallProfile {
    param($Name, [switch]$ErrorAction)
    $s = $Global:FakeFirewall[$Name]
    if (-not $s) { throw "FakeWindowsSystem: firewall profile not seeded: $Name" }
    return [PSCustomObject]@{
        Enabled = $s.Enabled
        DefaultInboundAction = $s.DefaultInboundAction
        DefaultOutboundAction = $s.DefaultOutboundAction
    }
}

function Set-NetFirewallProfile {
    param($Name, $Enabled, $DefaultInboundAction, $DefaultOutboundAction)
    $Global:FakeFirewall[$Name] = @{
        Enabled = $true
        DefaultInboundAction = $DefaultInboundAction
        DefaultOutboundAction = $DefaultOutboundAction
    }
}
"""
