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
    [string]$Profile = "L1",
    [string]$Platform = "server",
    [string]$Benchmark = "CIS Microsoft Windows Server Benchmark",
    [string]$Out = "result.json",
    [string]$BackupDir = "$env:TEMP\cis-backups",
    [switch]$AllowDisruptive,
    [string]$Include = "",
    [string]$Exclude = "",
    [string]$Sections = "",
    [string]$Families = ""
)

$ErrorActionPreference = "Stop"
$startedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz")
$sw = [System.Diagnostics.Stopwatch]::StartNew()

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

function Test-RegValue {
    param($Path, $Name, $Expected, $Op = "eq")
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
        switch ($Op) {
            "eq"  { return $val -eq $Expected }
            "le"  { return $val -le $Expected }
            "ge"  { return $val -ge $Expected }
            "ne"  { return $val -ne $Expected }
            "in"  { return $val -in $Expected }
            default { return $false }
        }
    } catch { return $false }
}

function Get-SecPol {
    param($Area, $Key)
    try {
        $tmp = "$env:TEMP\secpol_$([Guid]::NewGuid()).inf"
        secedit /export /cfg $tmp /areas $Area 2>$null | Out-Null
        if (Test-Path $tmp) {
            $content = Get-Content $tmp -Raw
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            if ($content -match "(?m)^\s*$Key\s*=\s*(.+)$") {
                return $Matches[1].Trim()
            }
        }
    } catch {}
    return $null
}

# ── Checks ─────────────────────────────────────────────────
function Invoke-Check {
    param($Rule, $Ctx)

    $id = $Rule.id
    $family = $Rule.family
    $params = $Rule.params

    switch ($family) {

        # ── 1. Account Policies ──
        "password-policy" {
            $key = $params.key
            $expected = $params.expected
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($val -ne $null) {
                $ok = ($val -ge $expected) -or ($params.op -eq "eq" -and $val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$key=$val (expected ≥$expected)"}
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
            $key = $params.key
            $expected = $params.expected
            $op = if ($params.op) { $params.op } else { "le" }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($val -ne $null) {
                if ($op -eq "le") { $ok = [int]$val -le [int]$expected }
                elseif ($op -eq "ge") { $ok = [int]$val -ge [int]$expected }
                else { $ok = ($val -eq $expected) }
                return @{status=if($ok){"pass"}else{"fail"}; detail="$key=$val (expected $op $expected)"}
            }
            return @{status="error"; detail="$key not found"}
        }

        # ── 3. Audit Policy ──
        "audit-policy" {
            $subcategory = $params.subcategory
            $expected = $params.expected
            try {
                $out = auditpol /get /subcategory:"$subcategory" 2>&1 | Out-String
                if ($out -match "$subcategory\s+(.+)$") {
                    $actual = $Matches[1].Trim()
                    $ok = ($actual -eq $expected)
                    return @{status=if($ok){"pass"}else{"fail"}; detail="$subcategory = $actual (expected $expected)"}
                }
            } catch {}
            return @{status="error"; detail="Failed to query audit policy: $subcategory"}
        }

        # ── 4. User Rights Assignment ──
        "user-right" {
            $privilege = $params.privilege
            $expectedSid = $params.expected_sid
            try {
                $tmp = "$env:TEMP\ur_$([Guid]::NewGuid()).inf"
                secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                if (Test-Path $tmp) {
                    $content = Get-Content $tmp -Raw
                    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                    if ($content -match "(?m)^\s*$privilege\s*=\s*(.+)$") {
                        $sids = $Matches[1].Trim() -split ','
                        $ok = ($sids | Where-Object { $_.Trim() -eq $expectedSid })
                        return @{status=if($ok){"pass"}else{"fail"}; detail="$privilege members: $($Matches[1].Trim())"}
                    }
                }
            } catch {}
            return @{status="error"; detail="Failed to query $privilege"}
        }

        # ── 5. Security Options (Registry) ──
        "reg-dword" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="Registry key not found: $path\$name"} }
        }

        "reg-string" {
            $path = $params.path
            $name = $params.name
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $params.value)
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
            $profile = $params.profile
            try {
                $fw = Get-NetFirewallProfile -Name $profile -ErrorAction Stop
                $enabled = $fw.Enabled
                $defaultIn = $fw.DefaultInboundAction
                $defaultOut = $fw.DefaultOutboundAction
                $ok = ($enabled -eq "True" -and $defaultIn -eq "Block" -and $defaultOut -eq "Allow")
                return @{
                    status = if($ok){"pass"}else{"fail"}
                    detail = "${profile}: enabled=$enabled inbound=$defaultIn outbound=$defaultOut"
                }
            } catch {
                return @{status="error"; detail="Failed to query firewall profile $profile"}
            }
        }

        # ── 7. Service Configuration ──
        "service-state" {
            $name = $params.name
            $expected = $params.state
            try {
                $svc = Get-Service -Name $name -ErrorAction Stop
                $ok = ($svc.Status -eq $expected -or $svc.StartType -eq $expected)
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
                $ok = ($val -eq $expected)
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
                $ok = ($val -eq $expected)
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
                $ok = ($val -ge $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="LmCompatibilityLevel = $val (expected ≥$expected)"}
            } catch { return @{status="error"; detail="LSA key not found"} }
        }

        "smb-signing" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
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
                $ok = ($val -eq $expected)
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
                    $ok = ($val -eq $expected)
                    return @{status=if($ok){"pass"}else{"fail"}; detail="PS logging $name=$val"}
                }
            } catch {}
            return @{status="fail"; detail="PS logging key not found"}
        }

        default {
            return @{status="error"; detail="Unknown family: $family"}
        }
    }
}

# ── Load Rules ──────────────────────────────────────────────
Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue
[Console]::WriteLine("DBG: JSS type available: $([System.Web.Script.Serialization.JavaScriptSerializer].FullName)")
$jss = New-Object System.Web.Script.Serialization.JavaScriptSerializer
[Console]::WriteLine("DBG: jss=$($jss.GetType().FullName)")
try {
    $raw = [System.IO.File]::ReadAllText($Catalog)
    [Console]::WriteLine("DBG: raw first 50 chars: $($raw.Substring(0, [Math]::Min(50, $raw.Length)))")
    $catalog = $jss.DeserializeObject($raw)
    [Console]::WriteLine("DBG: catalog=$($catalog.GetType().FullName) cnt=$($catalog.Count)")
} catch {
    [Console]::WriteLine("DBG ERROR: $_")
}
[Console]::WriteLine("DBG: Profile=[$Profile] Platform=[$Platform]")

$includeList = if ($Include) { $Include -split ',' | % { $_.Trim() } } else { @() }
$excludeList = if ($Exclude) { $Exclude -split ',' | % { $_.Trim() } } else { @() }
$sectionList = if ($Sections) { $Sections -split ',' | % { $_.Trim() } } else { @() }
$familyList  = if ($Families)  { $Families  -split ',' | % { $_.Trim() } } else { @() }

# Filter rules
$rules = @()
foreach ($r in $catalog) {
    # Level filter
    if ($Profile -eq "L1" -and $r.levels -notcontains 1) { continue }
    # Platform filter
    if ($Platform -and $r.platforms -and $r.platforms -notcontains $Platform) { continue }
    # Include/Exclude
    if ($includeList.Count -gt 0) {
        $match = $false
        foreach ($p in $includeList) { if ($r.id.StartsWith($p)) { $match = $true; break } }
        if (-not $match) { continue }
    }
    foreach ($p in $excludeList) { if ($r.id.StartsWith($p)) { continue } }
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
$count = 0
$total = $rules.Count

foreach ($rule in $rules) {
    $count++
    Write-Progress -Activity "CIS Scan" -Status "$($rule.id): $($rule.title)" -PercentComplete (($count / $total) * 100)
    $rsw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = Invoke-Check -Rule $rule
        $rsw.Stop()
        Write-Result -Id $rule.id -Title $rule.title -Section $rule.section `
            -Status $result.status -Level ($rule.levels | Select-Object -First 1) `
            -Assessment $rule.assessment -Family $rule.family `
            -Risk $rule.risk -Detail $result.detail -Page $rule.page `
            -Levels @($rule.levels)
    } catch {
        $rsw.Stop()
        Write-Result -Id $rule.id -Title $rule.title -Section $rule.section `
            -Status "error" -Level ($rule.levels | Select-Object -First 1) `
            -Assessment $rule.assessment -Family $rule.family `
            -Risk $rule.risk -Detail "Engine error: $_" -Page $rule.page `
            -Levels @($rule.levels)
    }
    $global:Results[-1].duration_ms = $rsw.ElapsedMilliseconds
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
    return @{
        total = $total; pass = $pass; fail = $fail; manual = $manual; error = $error
        notapplicable = $na; skipped_by_selection = 0; assessed = $assessed
        applied = 0; applied_pending = 0; score = $score
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
    engine_version = "1.0.0-windows"
    duration_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    started_at = $startedAt
    score = $overallScore
    summary = $summary
    results = @($global:Results)
    excluded = @()
    changed_files = @()
    engine_notes = @()
}

$output | ConvertTo-Json -Depth 4 | Out-File -FilePath $Out -Encoding utf8
Write-Host "CIS scan complete: $total rules, score=$overallScore%, pass=$($summary.all.pass), fail=$($summary.all.fail)"
Write-Host "Result written to: $Out"