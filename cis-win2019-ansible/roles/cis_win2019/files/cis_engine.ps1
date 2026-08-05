<#
.SYNOPSIS
CIS Windows Server Benchmark — assessment engine.
Driven by rules.json catalog, outputs result.json.

.PARAMETER Catalog
Path to rules.json
.PARAMETER Mode
scan | apply
.PARAMETER Profile
L1 | L2
.PARAMETER Out
Output JSON path (default: result.json)
#>

param(
    [string]$Catalog = "rules.json",
    [string]$Mode = "scan",
    [string]$ProfileLevel = "L1",
    [string]$Platform = "server",
    [string]$Out = "result.json",
    [string]$Include = "",
    [string]$Exclude = "",
    [string]$Sections = "",
    [string]$Families = "",

    [string]$AuditLog = "",
    [switch]$AllowDisruptive
)

if ($Mode -notin @("scan", "apply")) {
    Write-Error "Mode must be 'scan' or 'apply'. Got: $Mode"
    exit 1
}
if ($ProfileLevel -notin @("L1", "L2")) {
    Write-Error "Profile must be 'L1' or 'L2'. Got: $ProfileLevel"
    exit 1
}

$ErrorActionPreference = "Stop"
$startedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz")
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$auditWriter = $null
if ($AuditLog) {
    try {
        $auditWriter = [System.IO.StreamWriter]::new($AuditLog, $false, [System.Text.Encoding]::UTF8)
    } catch {
        Write-Host "audit-log: cannot open $AuditLog : $_"
    }
}
$hostname = [System.Net.Dns]::GetHostName()

# Ensure the audit StreamWriter handle is always released, even on a terminating
# error anywhere below (ErrorActionPreference=Stop would otherwise leak it).
trap {
    if ($auditWriter) {
        try { $auditWriter.Flush(); $auditWriter.Dispose() } catch { }
  $script:auditWriter = $null
    }
    break
}

# ── Helpers ────────────────────────────────────────────────
function Write-Result {
    param($Id, $Title, $Section, $Status, $Level, $Assessment = "Automated",
          $Family = "", $Risk = "safe", $Detail = "", $Page = 0, $Levels = @())
    $global:Results += [PSCustomObject]@{
        id = $Id; title = $Title; section = $Section; status = $Status
        level = $Level; assessment = $Assessment; family = $Family
        risk = $Risk; detail = $Detail; page = $Page; levels = $Levels
        duration_ms = 0; apply_status = "n/a"
    }
}

function Write-Audit {
    param($RuleId, $Title, $Status, $ApplyStatus, $Detail, $DurationMs)
    if (-not $auditWriter) { return }
    $entry = @{
        ts = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fff") + "Z"
        host = $hostname
        version = "1.1.0-windows"
     mode = $Mode
        profile = $ProfileLevel
    rule = $RuleId
        title = $Title
        status = $Status
        apply_status = $ApplyStatus
        detail = if ($Detail -and $Detail.Length -gt 200) { $Detail.Substring(0, 200) } else { $Detail }
        duration_ms = $DurationMs
    }
    $auditWriter.WriteLine(($entry | ConvertTo-Json -Compress))
    $auditWriter.Flush()
}

function Get-SecPol {
    param($Area, $Key)
    $tmp = $null
    try {
        $tmp = "$env:TEMP\secpol_$([Guid]::NewGuid()).inf"
        secedit /export /cfg $tmp /areas $Area 2>$null | Out-Null
        if (Test-Path $tmp) {
            $content = Get-Content $tmp -Raw
            if ($content -match "(?m)^\s*$([regex]::Escape($Key))\s*=\s*(.+)$") {
                return $Matches[1].Trim()
            }
        }
    } catch { Write-Debug "Get-SecPol failed: $_" }
    finally {
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    return $null
}

# ── Value comparison helpers (culture-invariant, type-tolerant) ──
function ConvertTo-InvariantInt {
    param($Value, [ref]$Ok)
    $parsed = 0
    $Ok.Value = [int]::TryParse(
        [string]$Value, [Globalization.NumberStyles]::Integer,
   [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)
    return $parsed
}

function Test-ValueEq {
    # Registry DWORDs come back as [int]; JSON expected may be int or string.
    # Compare numerically when both look numeric, otherwise fall back to string.
    param($Actual, $Expected)
    $aOk = $false; $eOk = $false
    $ai = ConvertTo-InvariantInt $Actual   ([ref]$aOk)
    $ei = ConvertTo-InvariantInt $Expected ([ref]$eOk)
    if ($aOk -and $eOk) { return ($ai -eq $ei) }
    return ("$Actual" -eq "$Expected")
}

# ── Policy name → (secedit key, expected, op) ──
$PasswordPolicyMap = @{
    "1" = @{ Key = "PasswordHistorySize";   Expected = 24;  Op = "ge" }
    "2" = @{ Key = "MaximumPasswordAge";    Expected = 365; Op = "le" }
    "3" = @{ Key = "MinimumPasswordAge";    Expected = 1;   Op = "ge" }
    "4" = @{ Key = "MinimumPasswordLength"; Expected = 14;  Op = "ge" }
    "5" = @{ Key = "PasswordComplexity";    Expected = 1;   Op = "eq" }
    "7" = @{ Key = "ClearTextPassword";     Expected = 0;   Op = "eq" }
}

$LockoutPolicyMap = @{
    "1" = @{ Key = "LockoutDuration";  Expected = 15; Op = "ge" }
    "2" = @{ Key = "LockoutBadCount";  Expected = 5;  Op = "le" }
    "4" = @{ Key = "ResetLockoutCount"; Expected = 15; Op = "ge" }
}

# Registry-based policies (not in secedit)
$PasswordRegMap = @{
    "6" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Sam"; Name = "RelaxMinimumPasswordLengthLimits"; Value = 1; Title = "Relax minimum password length limits" }
}
$LockoutRegMap = @{
    "3" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LimitBlankPasswordUse"; Value = 1; Title = "Allow Administrator account lockout" }
}

# Security Options audit policies (registry-based, not auditpol)
$AuditPolicyRegMap = @{
    "1" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "SCENoApplyLegacyAuditPolicy"; Value = 1; Summary = "Force audit policy subcategory settings" }
    "2" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "CrashOnAuditFail"; Value = 0; Summary = "Shut down system if unable to log security audits" }
}

# ── Checks ─────────────────────────────────────────────────
function Invoke-Check {
    param($Rule)

    $family = $Rule.family
    $params = $Rule.params

    switch ($family) {

        # ── 1. Account Policies ──
        "password-policy" {
            $pn = $params.policy_name
            if ($pn) {
                if ($PasswordPolicyMap.ContainsKey($pn)) {
                    $m = $PasswordPolicyMap[$pn]; $key = $m.Key; $expected = $m.Expected; $op = $m.Op
                } elseif ($PasswordRegMap.ContainsKey($pn)) {
                    $m = $PasswordRegMap[$pn]
                    try {
                        $val = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name
                       $ok = (Test-ValueEq $val $m.Value)
                        return @{status=if($ok){"pass"}else{"fail"}; detail="$($m.Title)=$val (expected $($m.Value))"}
                    } catch { return @{status="error"; detail="Registry key not found: $($m.Path)\$($m.Name)"} }
                } else {
                    return @{status="error"; detail="Unknown policy_name: $pn"}
                }
            } else {
                $key = $params.key; $expected = $params.expected
                $op = if ($params.op) { $params.op } else { "ge" }
            }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -ne $val) {
                $ok = if ($op -eq "ge") { [int]$val -ge [int]$expected }
                      elseif ($op -eq "le") { [int]$val -le [int]$expected }
                      else { $val -eq $expected }
                return @{status=if($ok){"pass"}else{"fail"}; detail="$key=$val (expected $op $expected)"}
            }
            return @{status="error"; detail="$key not found in security policy"}
        }

        "password-complexity" {
            $val = Get-SecPol "SECURITYPOLICY" "PasswordComplexity"
            $ok = ($val -eq "1")
            return @{status=if($ok){"pass"}else{"fail"}; detail="PasswordComplexity=$val"}
        }

        "password-reversible" {
            $val = Get-SecPol "SECURITYPOLICY" "ClearTextPassword"
            $ok = ($val -eq "0")
            return @{status=if($ok){"pass"}else{"fail"}; detail="ClearTextPassword=$val"}
        }

        # ── 2. Account Lockout ──
        "lockout-policy" {
            $pn = $params.policy_name
            if ($pn) {
                if ($LockoutPolicyMap.ContainsKey($pn)) {
                    $m = $LockoutPolicyMap[$pn]; $key = $m.Key; $expected = $m.Expected; $op = $m.Op
                } elseif ($LockoutRegMap.ContainsKey($pn)) {
                    $m = $LockoutRegMap[$pn]
                    try {
                        $val = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name
                       $ok = (Test-ValueEq $val $m.Value)
                        return @{status=if($ok){"pass"}else{"fail"}; detail="$($m.Title)=$val (expected $($m.Value))"}
                    } catch { return @{status="error"; detail="Registry key not found: $($m.Path)\$($m.Name)"} }
                } else {
                    return @{status="error"; detail="Unknown policy_name: $pn"}
                }
            } else {
                $key = $params.key; $expected = $params.expected
                $op = if ($params.op) { $params.op } else { "le" }
            }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -ne $val) {
                if ($op -eq "le") { $ok = [int]$val -le [int]$expected }
                elseif ($op -eq "ge") { $ok = [int]$val -ge [int]$expected }
                 else { $ok = (Test-ValueEq $val $expected) }
                return @{status=if($ok){"pass"}else{"fail"}; detail="$key=$val (expected $op $expected)"}
            }
            return @{status="error"; detail="$key not found"}
        }

        # ── 3. Audit Policy ──
        "audit-policy" {
            $policy = $params.policy
            if ($AuditPolicyRegMap.ContainsKey($policy)) {
                $m = $AuditPolicyRegMap[$policy]
                try {
                    $val = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name
                   $ok = (Test-ValueEq $val $m.Value)
                       return @{status=if($ok){"pass"}else{"fail"}; detail="$($m.Summary): $($m.Name)=$val (expected $($m.Value))"}
                } catch { return @{status="error"; detail="Registry key not found: $($m.Path)\$($m.Name)"} }
            }
            return @{status="error"; detail="Unknown audit policy index: $policy"}
        }

        # ── 4. User Rights Assignment ──
        "user-right" {
            $privilege = $params.privilege
            $expectedSid = $params.expected_sid
            $tmp = $null
            try {
                $tmp = "$env:TEMP\ur_$([Guid]::NewGuid()).inf"
                secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                if (Test-Path $tmp) {
                    $content = Get-Content $tmp -Raw
                    if ($content -match "(?m)^\s*$([regex]::Escape($privilege))\s*=\s*(.+)$") {
                        $sids = $Matches[1].Trim() -split ','
                        $ok = ($sids | Where-Object { $_.Trim() -eq $expectedSid })
                        return @{status=if($ok){"pass"}else{"fail"}; detail="$privilege members: $($Matches[1].Trim())"}
                    }
                }
            } catch { Write-Debug "user-right check failed: $_" }
            finally {
                if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
            }
            return @{status="error"; detail="Failed to query $privilege"}
        }

        # ── 5. Security Options (Registry) ──
        "reg-dword" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
           $ok = (Test-ValueEq $val $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="Registry key not found: $path\$name"} }
        }

        "reg-string" {
            $path = $params.path
            $name = $params.name
            try {
        $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
      $ok = ("$val" -ieq "$($params.value)")
    return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = '$val' (expected '$($params.value)')"}
            } catch { return @{status="error"; detail="Registry key not found: $path\$name"} }
        }

        "reg-exists" {
            $path = $params.path
            $ok = Test-Path $path
            return @{status=if($ok){"pass"}else{"fail"}; detail="$path exists=$ok"}
        }

        # ── 6. Windows Firewall ──
        "firewall-profile" {
            $fwProfile = $params.profile
       $expectedOut = if (($params.PSObject.Properties.Name -contains 'outbound') -and $params.outbound) { $params.outbound } else { "Allow" }
     try {
                $fw = Get-NetFirewallProfile -Name $fwProfile -ErrorAction Stop
   $enabled = $fw.Enabled
      $defaultIn = $fw.DefaultInboundAction
                $defaultOut = $fw.DefaultOutboundAction
     $ok = ("$enabled" -eq "True" -and "$defaultIn" -eq "Block" -and "$defaultOut" -eq "$expectedOut")
       return @{
  status = if($ok){"pass"}else{"fail"}
        detail = "${fwProfile}: enabled=$enabled inbound=$defaultIn outbound=$defaultOut (expected out=$expectedOut)"
 }
            } catch {
return @{status="error"; detail="Failed to query firewall profile $fwProfile"}
            }
        }

        # ── 7. Service Configuration ──
"service-state" {
     $name = $params.name
    $expected = $params.state
            try {
           $svc = Get-Service -Name $name -ErrorAction Stop
                # Match against the correct dimension: run-state vs start-type,
       # instead of an -or that passes when EITHER matches (false pass).
     $startTypes = @("Automatic", "Manual", "Disabled", "Auto", "AutomaticDelayedStart")
                $runStates  = @("Running", "Stopped", "Paused")
                if ($startTypes -contains $expected) {
           $ok = ("$($svc.StartType)" -eq "$expected" -or ("$expected" -eq "Auto" -and "$($svc.StartType)" -eq "Automatic"))
           } elseif ($runStates -contains $expected) {
    $ok = ("$($svc.Status)" -eq "$expected")
        } else {
           $ok = ("$($svc.Status)" -eq "$expected" -or "$($svc.StartType)" -eq "$expected")
      }
            return @{
      status = if($ok){"pass"}else{"fail"}
         detail = "${name}: status=$($svc.Status) startType=$($svc.StartType) (expected $expected)"
           }
 } catch {
                if ($expected -eq "NotFound") {
                    return @{status="pass"; detail="${name}: not installed (expected)"}
                }
                return @{status="fail"; detail="${name}: not found (expected $expected)"}
            }
        }

        # ── 8. Windows Update ──
        "wu-config" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
           $ok = (Test-ValueEq $val $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="WindowsUpdate\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="WU key not found"} }
        }

        # ── 9. UAC ──
        "uac" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
           $ok = (Test-ValueEq $val $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="UAC\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="UAC key not found"} }
        }

        # ── 10. Network Security ──
        "lanman-auth" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ([int]$val -ge [int]$expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="LmCompatibilityLevel = $val (expected ≥$expected)"}
            } catch { return @{status="error"; detail="LSA key not found"} }
        }

        "smb-signing" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
           $ok = (Test-ValueEq $val $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="SMB\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="SMB key not found"} }
        }

        # ── 11. RDP Security ──
        "rdp-nla" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
           $ok = (Test-ValueEq $val $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="RDP NLA = $val (expected $expected)"}
            } catch { return @{status="error"; detail="RDP key not found"} }
        }

        # ── 12. Event Log ──
        "eventlog-size" {
            $logName = $params.log
            $expectedMB = $params.min_size_mb
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
                $ok = ($sizeMB -ge $expectedMB)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$logName max=$sizeMB MB (expected ≥$expectedMB MB)"}
            } catch { return @{status="error"; detail="Event log $logName not found"} }
        }

        # ── 13. PowerShell Security ──
        "ps-execution" {
            try {
                $policy = Get-ExecutionPolicy -Scope LocalMachine
                $ok = ($policy -eq "RemoteSigned" -or $policy -eq "Restricted" -or $policy -eq "AllSigned")
                return @{status=if($ok){"pass"}else{"fail"}; detail="ExecutionPolicy=$policy"}
            } catch { return @{status="error"; detail="Failed to query execution policy"} }
        }

        "ps-logging" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                if (Test-Path $path) {
                    $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
               $ok = (Test-ValueEq $val $expected)
                    return @{status=if($ok){"pass"}else{"fail"}; detail="PS logging $name=$val"}
                }
            } catch { Write-Debug "ps-logging check failed: $_" }
            return @{status="fail"; detail="PS logging key not found"}
        }

        default {
            return @{status="error"; detail="Unknown family: $family"}
        }
    }
}

# ── Apply (Remediation) ─────────────────────────────────────
function Invoke-Fix {
    param($Rule)

    $family = $Rule.family
    $params = $Rule.params

    switch ($family) {

        "password-policy" {
            $pn = $params.policy_name
            if ($pn) {
                if ($PasswordPolicyMap.ContainsKey($pn)) {
                    $m = $PasswordPolicyMap[$pn]; $key = $m.Key; $expected = $m.Expected; $op = $m.Op
                } elseif ($PasswordRegMap.ContainsKey($pn)) {
                    $m = $PasswordRegMap[$pn]
                    try { $cur = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name; if ($cur -eq $m.Value) { return "already" } } catch { Write-Debug "PasswordRegMap check failed: $_" }
                    try { if (-not (Test-Path $m.Path)) { New-Item -Path $m.Path -Force | Out-Null }; Set-ItemProperty -Path $m.Path -Name $m.Name -Value $m.Value -Type DWord -Force; return "applied" } catch { return "failed: $($_.Exception.Message)" }
                } else { return "error: unknown policy_name: $pn" }
            } else {
                $key = $params.key; $expected = $params.expected
                $op = if ($params.op) { $params.op } else { "ge" }
            }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -eq $val) { return "error: cannot read $key" }
            $isOk = if ($op -eq "ge") { [int]$val -ge [int]$expected }
                    elseif ($op -eq "le") { [int]$val -le [int]$expected }
                    else { $val -eq $expected }
            if ($isOk) { return "already" }
            try {
                $tmpInf = "$env:TEMP\secpol_fix_$([Guid]::NewGuid()).inf"
                $seceditDb = "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb"
                secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                $c = Get-Content $tmpInf -Raw
                if ($c -match "(?m)^(\s*[^\s=]*\s*=\s*).+$") {
                    if ($c -match "(?m)^(\s*$([regex]::Escape($key))\s*=\s*).+$") {
                        $c = $c -replace "(?m)^(\s*$([regex]::Escape($key))\s*=\s*).+$", "`${1}$expected"
                    } else {
                        $c += "`r`n$key = $expected"
                    }
     [System.IO.File]::WriteAllText($tmpInf, $c)
        secedit /configure /db $seceditDb /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
     $rc = $LASTEXITCODE
        Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue
      Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
        if ($rc -ne 0) { return "failed: secedit exit code $rc" }
   return "applied"
  }
                Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
                return "error: secedit export was empty or invalid"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "lockout-policy" {
            $pn = $params.policy_name
            if ($pn) {
                if ($LockoutPolicyMap.ContainsKey($pn)) {
                    $m = $LockoutPolicyMap[$pn]; $key = $m.Key; $expected = $m.Expected; $op = $m.Op
                } elseif ($LockoutRegMap.ContainsKey($pn)) {
                    $m = $LockoutRegMap[$pn]
                    try { $cur = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name; if ($cur -eq $m.Value) { return "already" } } catch { Write-Debug "LockoutRegMap check failed: $_" }
                    try { if (-not (Test-Path $m.Path)) { New-Item -Path $m.Path -Force | Out-Null }; Set-ItemProperty -Path $m.Path -Name $m.Name -Value $m.Value -Type DWord -Force; return "applied" } catch { return "failed: $($_.Exception.Message)" }
                } else { return "error: unknown policy_name: $pn" }
            } else {
                $key = $params.key; $expected = $params.expected
                $op = if ($params.op) { $params.op } else { "le" }
            }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -eq $val) { return "error: cannot read $key" }
            $isOk = if ($op -eq "le") { [int]$val -le [int]$expected }
                    elseif ($op -eq "ge") { [int]$val -ge [int]$expected }
                    else { $val -eq $expected }
            if ($isOk) { return "already" }
            try {
                $tmpInf = "$env:TEMP\secpol_fix_$([Guid]::NewGuid()).inf"
                $seceditDb = "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb"
                secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                $c = Get-Content $tmpInf -Raw
                if ($c -match "(?m)^(\s*[^\s=]*\s*=\s*).+$") {
                    if ($c -match "(?m)^(\s*$([regex]::Escape($key))\s*=\s*).+$") {
                        $c = $c -replace "(?m)^(\s*$([regex]::Escape($key))\s*=\s*).+$", "`${1}$expected"
                    } else {
                        $c += "`r`n$key = $expected"
                    }
     [System.IO.File]::WriteAllText($tmpInf, $c)
        secedit /configure /db $seceditDb /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
     $rc = $LASTEXITCODE
        Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue
      Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
        if ($rc -ne 0) { return "failed: secedit exit code $rc" }
   return "applied"
  }
                Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
                return "error: secedit export was empty or invalid"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "audit-policy" {
            $policy = $params.policy
            if ($AuditPolicyRegMap.ContainsKey($policy)) {
                $m = $AuditPolicyRegMap[$policy]
                try { $cur = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name; if ($cur -eq $m.Value) { return "already" } } catch { Write-Debug "AuditPolicyRegMap check failed: $_" }
                try { if (-not (Test-Path $m.Path)) { New-Item -Path $m.Path -Force | Out-Null }; Set-ItemProperty -Path $m.Path -Name $m.Name -Value $m.Value -Type DWord -Force; return "applied" } catch { return "failed: $($_.Exception.Message)" }
            }
            return "error: unknown audit policy index: $policy"
        }

        "user-right" {
            $privilege = $params.privilege; $expectedSid = $params.expected_sid
            if (-not $expectedSid) { return "skipped: no expected SID defined" }
     try {
             $tmp = "$env:TEMP\ur_$([Guid]::NewGuid()).inf"
       secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
       if (Test-Path $tmp) {
            $c = Get-Content $tmp -Raw
    if ($c -match "(?m)^\s*$([regex]::Escape($privilege))\s*=\s*(.+)$") {
       # Exact token match (split on comma) — avoids substring collisions between SIDs
        $members = $Matches[1].Trim() -split ',' | ForEach-Object { $_.Trim() }
   if ($members -contains $expectedSid.Trim()) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue; return "already" }
    }
    }
      Remove-Item $tmp -Force -ErrorAction SilentlyContinue
       $tmp2 = "$env:TEMP\ur_fix_$([Guid]::NewGuid()).inf"
   secedit /export /cfg $tmp2 /areas USER_RIGHTS 2>$null | Out-Null
     $c = Get-Content $tmp2 -Raw
     if ($c -match "(?m)^(\s*$([regex]::Escape($privilege))\s*=\s*).+$") {
      $c = $c -replace "(?m)^(\s*$([regex]::Escape($privilege))\s*=\s*).+$", "`${1}$expectedSid"
       } else {
      $c += "`r`n$privilege = $expectedSid"
            }
  [System.IO.File]::WriteAllText($tmp2, $c)
     $seceditDb = "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb"
           secedit /configure /db $seceditDb /cfg $tmp2 /areas USER_RIGHTS 2>$null | Out-Null
    $rc = $LASTEXITCODE
     Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue
  Remove-Item $tmp2 -Force -ErrorAction SilentlyContinue
   if ($rc -ne 0) { return "failed: secedit exit code $rc" }
     return "applied"
         } catch { return "failed: $($_.Exception.Message)" }
        }

        "reg-dword" {
            $path = $params.path; $name = $params.name; $expected = $params.value
            try {
                $current = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                if ($current -eq $expected) { return "already" }
            } catch { Write-Debug "reg-dword check failed: $_" }
            try {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWord -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "firewall-profile" {
   $fwProfile = $params.profile
     $expectedOut = if (($params.PSObject.Properties.Name -contains 'outbound') -and $params.outbound) { $params.outbound } else { "Allow" }
     try {
     $fw = Get-NetFirewallProfile -Name $fwProfile -ErrorAction Stop
     if ("$($fw.Enabled)" -eq "True" -and "$($fw.DefaultInboundAction)" -eq "Block" -and "$($fw.DefaultOutboundAction)" -eq "$expectedOut") { return "already" }
    Set-NetFirewallProfile -Name $fwProfile -Enabled True -DefaultInboundAction Block -DefaultOutboundAction $expectedOut
        return "applied"
 } catch { return "failed: $($_.Exception.Message)" }
    }

  "service-state" {
   $name = $params.name; $expected = $params.state
 try {
          $svc = Get-Service -Name $name -ErrorAction Stop
     if ($expected -eq "Stopped" -and "$($svc.Status)" -eq "Stopped" -and "$($svc.StartType)" -eq "Disabled") { return "already" }
     if ($expected -eq "Disabled" -and "$($svc.StartType)" -eq "Disabled") { return "already" }
       if ($expected -eq "Running" -and "$($svc.Status)" -eq "Running") { return "already" }
    if (("$($svc.StartType)" -eq "Automatic") -and ($expected -eq "Auto" -or $expected -eq "Automatic")) { return "already" }
   if ($expected -eq "Manual" -and "$($svc.StartType)" -eq "Manual") { return "already" }
 if ($expected -eq "Stopped" -or $expected -eq "Disabled") {
   Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    Set-Service -Name $name -StartupType Disabled
       } elseif ($expected -eq "Running") {
     Set-Service -Name $name -StartupType Automatic
       Start-Service -Name $name -ErrorAction SilentlyContinue
    } elseif ($expected -eq "Auto" -or $expected -eq "Automatic") {
     Set-Service -Name $name -StartupType Automatic
     } elseif ($expected -eq "Manual") {
     Set-Service -Name $name -StartupType Manual
       } else {
              return "skipped: unsupported service state '$expected'"
   }
             return "applied"
     } catch {
           if ($expected -eq "NotFound") { return "already" }
       return "failed: $($_.Exception.Message)"
   }
        }

        "smb-signing" {
            $path = $params.path; $name = $params.name; $expected = $params.value
            try {
                $current = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                if ($current -eq $expected) { return "already" }
            } catch { Write-Debug "smb-signing check failed: $_" }
            try {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWord -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "rdp-nla" {
            $path = $params.path; $name = $params.name; $expected = $params.value
            try {
                $current = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                if ($current -eq $expected) { return "already" }
            } catch { Write-Debug "rdp-nla check failed: $_" }
            try {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWord -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "eventlog-size" {
            $logName = $params.log; $expectedMB = $params.min_size_mb
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
                if ($sizeMB -ge $expectedMB) { return "already" }
                $log.MaximumSizeInBytes = $expectedMB * 1MB
                $log.SaveChanges()
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "ps-execution" {
            try {
                $policy = Get-ExecutionPolicy -Scope LocalMachine
                if ($policy -eq "RemoteSigned" -or $policy -eq "Restricted" -or $policy -eq "AllSigned") {
                    return "already"
                }
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "ps-logging" {
            $path = $params.path; $name = $params.name; $expected = $params.value
            try {
                if (Test-Path $path) {
                    $current = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                    if ($current -eq $expected) { return "already" }
                }
            } catch { Write-Debug "ps-logging fix check failed: $_" }
            try {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWord -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        default { return "skipped: no fix for family $family" }
    }
}

# ── Load Rules ──────────────────────────────────────────────
try {
    $raw = [System.IO.File]::ReadAllText($Catalog)
    $catalog = $raw | ConvertFrom-Json
    if (-not $catalog -or $catalog.Count -eq 0) {
        Write-Error "Catalog is empty or failed to parse: $Catalog"
        if ($auditWriter) { try { $auditWriter.Close() } catch {} }
        exit 1
    }
} catch {
    Write-Error "Failed to load rules catalog: $_"
    if ($auditWriter) { try { $auditWriter.Close() } catch {} }
    exit 1
}

$includeList = if ($Include) { $Include -split ',' | % { $_.Trim() } } else { @() }
$excludeList = if ($Exclude) { $Exclude -split ',' | % { $_.Trim() } } else { @() }
$sectionList = if ($Sections) { $Sections -split ',' | % { $_.Trim() } } else { @() }
$familyList  = if ($Families)  { $Families  -split ',' | % { $_.Trim() } } else { @() }

# Filter rules
$rules = @()
foreach ($r in $catalog) {
    # Level filter
       if ($ProfileLevel -eq "L1" -and $r.levels -notcontains 1) { continue }
    # Platform filter
    if ($Platform -and $r.platforms -and $r.platforms -notcontains $Platform) { continue }
    # Exclude — must check BEFORE adding to $rules
    $excluded = $false
    foreach ($p in $excludeList) { if ($r.id.StartsWith($p)) { $excluded = $true; break } }
    if ($excluded) { continue }
    # Include
    if ($includeList.Count -gt 0) {
        $match = $false
        foreach ($p in $includeList) { if ($r.id.StartsWith($p)) { $match = $true; break } }
        if (-not $match) { continue }
    }
    # Section filter
    if ($sectionList.Count -gt 0) {
        $match = $false
        foreach ($s in $sectionList) { if ($r.id.StartsWith($s)) { $match = $true; break } }
        if (-not $match) { continue }
    }
    # Families filter
    if ($familyList.Count -gt 0 -and $r.family) {
        $match = $false
        foreach ($f in $familyList) { if ($r.family -eq $f) { $match = $true; break } }
        if (-not $match) { continue }
    }
    $rules += $r
}

# ── Execute ─────────────────────────────────────────────────
$global:Results = @()
$global:Changed = @()
$count = 0
$total = $rules.Count
$isApply = ($Mode -eq "apply")

if ($isApply) {
    Write-Host "CIS apply mode: will remediate failed rules"
    if (-not $AllowDisruptive) {
        Write-Host "  Disruptive rules will be skipped (use -AllowDisruptive to include)"
    }
}

foreach ($rule in $rules) {
    $count++
    $activity = if ($isApply) { "CIS Apply" } else { "CIS Scan" }
    Write-Progress -Activity $activity -Status "$($rule.id): $($rule.title)" -PercentComplete (($count / $total) * 100)
    $rsw = [System.Diagnostics.Stopwatch]::StartNew()

    # Step 1: Always run the check
    try {
        $result = Invoke-Check -Rule $rule
    } catch {
        $rsw.Stop()
        Write-Result -Id $rule.id -Title $rule.title -Section $rule.section `
            -Status "error" -Level @($rule.levels) `
            -Assessment $rule.assessment -Family $rule.family `
            -Risk $rule.risk -Detail "Engine error: $_" -Page $rule.page `
            -Levels @($rule.levels)
        $global:Results[-1].duration_ms = $rsw.ElapsedMilliseconds
        Write-Audit -RuleId $rule.id -Title $rule.title `
            -Status "error" -ApplyStatus "n/a" -Detail "Engine error: $_" `
            -DurationMs $rsw.ElapsedMilliseconds
        continue
    }

    # Step 2: If apply mode and check failed (status=fail), try to fix
    $applyStatus = "n/a"
    if ($isApply -and $result.status -eq "fail") {
        # Skip disruptive rules unless explicitly allowed
        if ($rule.risk -eq "disruptive" -and -not $AllowDisruptive) {
            $applyStatus = "skipped_disruptive"
        } else {
            try {
                $applyStatus = Invoke-Fix -Rule $rule
                if ($applyStatus -eq "applied") {
                    $global:Changed += "$($rule.id): $($rule.title)"
                }
            } catch {
                $applyStatus = "failed: $($_.Exception.Message)"
            }
        }
    } elseif ($isApply -and $result.status -ne "fail") {
        $applyStatus = "already"
    }

    $rsw.Stop()
    Write-Result -Id $rule.id -Title $rule.title -Section $rule.section `
        -Status $result.status -Level @($rule.levels) `
        -Assessment $rule.assessment -Family $rule.family `
        -Risk $rule.risk -Detail $result.detail -Page $rule.page `
        -Levels @($rule.levels)
    $global:Results[-1].duration_ms = $rsw.ElapsedMilliseconds
    $global:Results[-1].apply_status = $applyStatus
    Write-Audit -RuleId $rule.id -Title $rule.title `
        -Status $result.status -ApplyStatus $applyStatus `
        -Detail $result.detail -DurationMs $rsw.ElapsedMilliseconds
}

# ── Summary ─────────────────────────────────────────────────
function Get-Summary($levelFilter) {
    $filtered = if ($levelFilter) { $global:Results | Where-Object { $_.level -eq $levelFilter } } else { $global:Results }
    $pass = ($filtered | Where-Object { $_.status -eq "pass" }).Count
    $fail = ($filtered | Where-Object { $_.status -eq "fail" }).Count
    $manual = ($filtered | Where-Object { $_.status -eq "manual" }).Count
    $error = ($filtered | Where-Object { $_.status -eq "error" }).Count
    $na = ($filtered | Where-Object { $_.status -eq "notapplicable" }).Count
    $total = $filtered.Count
    $assessed = $pass + $fail
    $score = if ($assessed -gt 0) { [math]::Round(100.0 * $pass / $assessed, 1) } else { 0.0 }

    # Apply stats
    $applied = ($filtered | Where-Object { $_.apply_status -eq "applied" }).Count
    $applyFailed = ($filtered | Where-Object { $_.apply_status -match "^failed" }).Count
    $skippedRisk = ($filtered | Where-Object { $_.apply_status -eq "skipped_disruptive" }).Count
    $already = ($filtered | Where-Object { $_.apply_status -eq "already" }).Count
        # Windows registry/secedit changes take effect immediately; there is no
    # reboot-pending queue to track, so applied_pending is always 0 by design.
    $appliedPending = 0

    return @{
        total = $total; pass = $pass; fail = $fail; manual = $manual; error = $error
        notapplicable = $na; skipped_by_selection = 0; assessed = $assessed
        applied = $applied; applied_pending = $appliedPending; score = $score
        apply_failed = $applyFailed; skipped_disruptive = $skippedRisk
        already = $already
    }
}

$sw.Stop()
$summary = @{
    all = Get-Summary $null
    L1 = Get-Summary 1
    L2 = Get-Summary 2
}
$overallScore = $summary.all.score

$output = @{
    mode = $Mode
    engine_version = "1.1.0-windows"
    duration_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    started_at = $startedAt
    score = $overallScore
    summary = $summary
    results = @($global:Results)
    excluded = @()
    changed_files = @($global:Changed)
    engine_notes = @()
}

$output | ConvertTo-Json -Depth 10 | Out-File -FilePath $Out -Encoding utf8
Write-Host "CIS scan complete: $($global:Results.Count) rules, score=$overallScore%, pass=$($summary.all.pass), fail=$($summary.all.fail)"
Write-Host "Result written to: $Out"
if ($auditWriter) {
    try { $auditWriter.Flush(); $auditWriter.Dispose() } catch { }
    $auditWriter = $null
    Write-Host "Audit log written to: $AuditLog"
}
# ── Exit with code based on failures ──
$failCount = ($global:Results | Where-Object { $_.status -eq "fail" }).Count
$errorCount = ($global:Results | Where-Object { $_.status -eq "error" }).Count
if ($errorCount -gt 0) { exit 2 }
if ($failCount -gt 0) { exit 1 }
exit 0
