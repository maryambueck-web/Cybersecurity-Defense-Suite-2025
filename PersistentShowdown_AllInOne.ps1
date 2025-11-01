<#
.SYNOPSIS
PERSISTENT SHOWDOWN - ALL-IN-ONE CYBERSECURITY SUITE
Complete educational cybersecurity challenge solution in a single PowerShell file

.DESCRIPTION
This comprehensive PowerShell script includes:
- Advanced defender with 8+ persistence mechanisms detection
- Educational malware for testing
- Persistent watchdog protection
- Comprehensive testing framework
- Competition automation
- Detailed reporting and logging
- Web server for remote deployment

Author: M. Bück
Date: November 1, 2025
Version: 2.0 - All-in-One Edition

.PARAMETER Mode
Operation mode: Defender, Attacker, Watchdog, Competition, Test, Deploy, WebServer, RealTime, AutoStart, Menu

.PARAMETER TargetFile
Target file path for defender operations (default: C:\Users\Public\Documents\pwned.txt)

.PARAMETER AutoRemediate
Run defender in automatic mode without prompts

.PARAMETER InstallWatchdog
Install persistent watchdog protection

.PARAMETER CollectorUrl
URL for report collection server

.PARAMETER ServerPort
Port for web server mode (default: 8000)

.EXAMPLE
# Run advanced defender
.\PersistentShowdown_AllInOne.ps1 -Mode Defender -AutoRemediate

# Create test environment and run competition
.\PersistentShowdown_AllInOne.ps1 -Mode Competition

# Install educational malware for testing
.\PersistentShowdown_AllInOne.ps1 -Mode Attacker -Action Install

# Start web server for remote deployment
.\PersistentShowdown_AllInOne.ps1 -Mode WebServer -ServerPort 8000

# Run comprehensive testing
.\PersistentShowdown_AllInOne.ps1 -Mode Test

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Defender", "Attacker", "Watchdog", "Competition", "Test", "Deploy", "WebServer", "RealTime", "AutoStart", "Menu")]
    [string]$Mode = "Menu",
    
    [Parameter(Mandatory=$false)]
    [string]$TargetFile = "C:\Users\Public\Documents\pwned.txt",
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoRemediate,
    
    [Parameter(Mandatory=$false)]
    [switch]$InstallWatchdog,
    
    [Parameter(Mandatory=$false)]
    [string]$CollectorUrl = "",
    
    [Parameter(Mandatory=$false)]
    [int]$ServerPort = 8000,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Payload", "Cleanup")]
    [string]$Action = "Install",
    
    [Parameter(Mandatory=$false)]
    [string]$QuarantinePath = "C:\Quarantine\PersistentShowdown_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [switch]$VerboseLog
)

Set-StrictMode -Version Latest
$global:LogEntries = @()

#region Core Functions

function Write-Banner {
    param([string]$Title, [string]$Color = "Cyan")
    $border = "=" * 60
    Write-Host $border -ForegroundColor $Color
    Write-Host "    $Title" -ForegroundColor $Color
    Write-Host $border -ForegroundColor $Color
    Write-Host ""
}

function Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("s")
    $entry = "$ts [$Level] $Message"
    Write-Output $entry
    $global:LogEntries += $entry
    if ($VerboseLog) { Write-Verbose $entry }
}

function Show-Menu {
    Write-Banner "🏆 PERSISTENT SHOWDOWN - ALL-IN-ONE SUITE" "Magenta"
    
    Write-Host "⚡ FOR COLLEAGUES: Use option 9 (AutoStart) for automatic protection!" -ForegroundColor Yellow
    Write-Host "   This installs protection that starts automatically when you boot your computer." -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "📋 Available Modes:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. 🛡️  Defender    - Advanced malware detection and removal" -ForegroundColor Green
    Write-Host "2. 🔴 Attacker    - Educational malware for testing" -ForegroundColor Red
    Write-Host "3. 👁️  Watchdog    - Persistent boot protection" -ForegroundColor Blue
    Write-Host "4. 🏆 Competition - Automated attacker vs defender showdown" -ForegroundColor Magenta
    Write-Host "5. 🧪 Test        - Comprehensive testing framework" -ForegroundColor Yellow
    Write-Host "6. 🚀 Deploy      - Create deployment environment" -ForegroundColor Cyan
    Write-Host "7. 🌐 WebServer   - HTTP server for remote deployment" -ForegroundColor White
    Write-Host "8. 🛡️ RealTime    - Active real-time protection system" -ForegroundColor Green
    Write-Host "9. ⚡ AutoStart   - Install automatic startup protection" -ForegroundColor Magenta
    Write-Host "0. ❌ Exit        - Close the application" -ForegroundColor Gray
    Write-Host ""
    Write-Host "💡 For colleagues: Use option 9 for automatic protection!" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host "Select mode (1-9, 0)"
    
    switch ($choice) {
        "1" { 
            Write-Host "🛡️ Starting Defender Mode..." -ForegroundColor Green
            Start-DefenderMode 
        }
        "2" { 
            Write-Host "🔴 Starting Attacker Mode..." -ForegroundColor Red
            Start-AttackerMode 
        }
        "3" { 
            Write-Host "👁️ Starting Watchdog Mode..." -ForegroundColor Blue
            Start-WatchdogMode 
        }
        "4" { 
            Write-Host "🏆 Starting Competition Mode..." -ForegroundColor Magenta
            Start-CompetitionMode 
        }
        "5" { 
            Write-Host "🧪 Starting Test Mode..." -ForegroundColor Yellow
            Start-TestMode 
        }
        "6" { 
            Write-Host "🚀 Starting Deploy Mode..." -ForegroundColor Cyan
            Start-DeployMode 
        }
        "7" { 
            Write-Host "🌐 Starting WebServer Mode..." -ForegroundColor White
            Start-WebServerMode 
        }
        "8" { 
            Write-Host "�️ Starting Real-Time Protection..." -ForegroundColor Green
            Start-RealTimeProtection
        }
        "9" { 
            Write-Host "�👋 Goodbye!" -ForegroundColor Gray
            exit 0 
        }
        default { 
            Write-Host "❌ Invalid choice. Please select 1-9." -ForegroundColor Red
            Start-Sleep 2
            Show-Menu 
        }
    }
}

function Test-Base64Content {
    param([string]$Content)
    if (-not $Content) { return $false }
    
    # Look for PowerShell encoded commands (most common in Choco.ps1)
    if ($Content -imatch '-EncodedCommand\s+([A-Za-z0-9+/=]+)') {
        try {
            $base64 = $matches[1]
            $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
            if ($decoded -imatch [regex]::Escape($TargetFile) -or $decoded -imatch 'pwned\.txt') {
                Log "🔓 Detected PowerShell EncodedCommand threat: $($decoded.Substring(0, [Math]::Min(100, $decoded.Length)))" "WARN"
                return $true
            }
        } catch {
            # Not valid Base64 or decoding failed
        }
    }
    
    # Look for -enc parameter (short form)
    if ($Content -imatch '-enc\s+([A-Za-z0-9+/=]+)') {
        try {
            $base64 = $matches[1]
            $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
            if ($decoded -imatch [regex]::Escape($TargetFile) -or $decoded -imatch 'pwned\.txt') {
                Log "🔓 Detected PowerShell -enc threat: $($decoded.Substring(0, [Math]::Min(100, $decoded.Length)))" "WARN"
                return $true
            }
        } catch {}
    }
    
    # Look for general Base64 patterns (20+ chars, proper padding)
    if ($Content -imatch '\b([A-Za-z0-9+/]{20,}={0,2})\b') {
        try {
            $base64 = $matches[1]
            if ($base64.Length % 4 -eq 0) {  # Valid Base64 length
                # Try Unicode first (PowerShell default)
                try {
                    $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
                    if ($decoded -imatch [regex]::Escape($TargetFile) -or $decoded -imatch 'pwned\.txt') {
                        Log "🔓 Detected Base64 Unicode content: $($decoded.Substring(0, [Math]::Min(50, $decoded.Length)))" "WARN"
                        return $true
                    }
                } catch {}
                
                # Try UTF8 if Unicode fails
                try {
                    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))
                    if ($decoded -imatch [regex]::Escape($TargetFile) -or $decoded -imatch 'pwned\.txt') {
                        Log "🔓 Detected Base64 UTF8 content: $($decoded.Substring(0, [Math]::Min(50, $decoded.Length)))" "WARN"
                        return $true
                    }
                } catch {}
                
                # Try ASCII as last resort
                try {
                    $decoded = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($base64))
                    if ($decoded -imatch [regex]::Escape($TargetFile) -or $decoded -imatch 'pwned\.txt') {
                        Log "🔓 Detected Base64 ASCII content: $($decoded.Substring(0, [Math]::Min(50, $decoded.Length)))" "WARN"
                        return $true
                    }
                } catch {}
            }
        } catch {
            # Not valid Base64 or decoding failed
        }
    }
    
    # Look for URL-safe Base64 (uses - and _ instead of + and /)
    if ($Content -imatch '\b([A-Za-z0-9_-]{20,}={0,2})\b') {
        try {
            $base64 = $matches[1] -replace '-', '+' -replace '_', '/'
            # Add padding if needed
            while ($base64.Length % 4 -ne 0) { $base64 += '=' }
            
            $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
            if ($decoded -imatch [regex]::Escape($TargetFile) -or $decoded -imatch 'pwned\.txt') {
                Log "🔓 Detected URL-safe Base64 threat: $($decoded.Substring(0, [Math]::Min(50, $decoded.Length)))" "WARN"
                return $true
            }
        } catch {}
    }
    
    return $false
}

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "⚠️ This script requires Administrator privileges for full functionality." -ForegroundColor Yellow
        Write-Host "Some features may not work correctly without elevation." -ForegroundColor Yellow
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -notmatch '^[Yy]') {
            Write-Host "Please run as Administrator for best results." -ForegroundColor Red
            exit 1
        }
    }
}

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Log "Created directory: $Path"
    }
}

function Backup-FileToQuarantine {
    param([string]$FilePath)
    New-Directory -Path $QuarantinePath
    if (-not (Test-Path $FilePath)) { return $null }
    $base = [IO.Path]::GetFileName($FilePath)
    $dest = Join-Path $QuarantinePath ("$((Get-Date).ToString('yyyyMMdd_HHmmss'))_$base")
    try {
        Copy-Item -Path $FilePath -Destination $dest -Force -ErrorAction Stop
        Log "Backed up file to quarantine: $FilePath -> $dest"
        return $dest
    } catch {
        Log "Failed to back up $FilePath to $dest : $_" "ERROR"
        return $null
    }
}

#endregion

#region Defender Functions

function Start-DefenderMode {
    Write-Banner "🛡️ ADVANCED PERSISTENT THREAT DEFENDER" "Green"
    Write-Host "🎯 Target protection: $TargetFile" -ForegroundColor Cyan
    Write-Host "🔬 Choco Intelligence: ACTIVE - Enhanced with Soroush's attack patterns" -ForegroundColor Yellow
    Write-Host "⏱️ Attack timeline: IFEO (30s), Registry (35-40s), Tasks (45-60s), Startup (50-55s), WMI (70s)" -ForegroundColor Gray
    Write-Host "🎲 Random naming: Detecting WindowsUpdateScan*, SecurityHealthSystray*, MicrosoftEdgeAutoLaunch*" -ForegroundColor Gray
    Write-Host ""
    
    if (-not $AutoRemediate) {
        Write-Host "Interactive Mode - You will be prompted for each action" -ForegroundColor Yellow
        Write-Host "Use -AutoRemediate for automatic operation" -ForegroundColor Gray
        Write-Host ""
    }
    
    Log "Defender starting. TargetFile=$TargetFile AutoRemediate=$AutoRemediate"
    
    # Initialize quarantine
    New-Directory -Path $QuarantinePath
    
    # Remove target file first
    if (Test-Path $TargetFile) {
        Log "Target file exists: $TargetFile"
        Backup-FileToQuarantine -FilePath $TargetFile | Out-Null
        if ($AutoRemediate -or (Read-Host "Delete target file $TargetFile? (Y/N)") -match '^[Yy]') {
            Remove-Item -Path $TargetFile -Force -ErrorAction SilentlyContinue
            Log "Deleted target file $TargetFile"
        }
    } else {
        Log "Target file not found: $TargetFile"
    }
    
    # Scan and remove persistence mechanisms
    $totalThreats = 0
    
    # Registry Run Keys
    $runEntries = Find-RunKeysReferencingTarget
    if ($runEntries.Count -gt 0) {
        Write-Host "🔍 Found $($runEntries.Count) malicious registry entries" -ForegroundColor Red
        $runEntries | ForEach-Object { Write-Host "  $($_.Key)\$($_.Name)" -ForegroundColor Gray }
        Remove-RunKeys -entries $runEntries
        $totalThreats += $runEntries.Count
    }
    
    # Startup Items
    $startupEntries = Find-StartupItemsReferencingTarget
    if ($startupEntries.Count -gt 0) {
        Write-Host "🔍 Found $($startupEntries.Count) malicious startup items" -ForegroundColor Red
        $startupEntries | ForEach-Object { Write-Host "  $($_.File)" -ForegroundColor Gray }
        Remove-StartupItems -items $startupEntries
        $totalThreats += $startupEntries.Count
    }
    
    # Scheduled Tasks
    $taskEntries = Find-ScheduledTasksReferencingTarget
    if ($taskEntries.Count -gt 0) {
        Write-Host "🔍 Found $($taskEntries.Count) malicious scheduled tasks" -ForegroundColor Red
        $taskEntries | ForEach-Object { Write-Host "  $($_.TaskName)" -ForegroundColor Gray }
        Remove-ScheduledTasks -tasks $taskEntries
        $totalThreats += $taskEntries.Count
    }
    
    # Services
    $svcEntries = Find-ServicesReferencingTarget
    if ($svcEntries.Count -gt 0) {
        Write-Host "🔍 Found $($svcEntries.Count) malicious services" -ForegroundColor Red
        $svcEntries | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Gray }
        Remove-Services -services $svcEntries
        $totalThreats += $svcEntries.Count
    }
    
    # WMI Subscriptions
    $wmiEntries = Find-WMISubscriptionsReferencingTarget
    if ($wmiEntries.Count -gt 0) {
        Write-Host "🔍 Found $($wmiEntries.Count) malicious WMI subscriptions" -ForegroundColor Red
        Remove-WMISubscriptions -entries $wmiEntries
        $totalThreats += $wmiEntries.Count
    }
    
    # PowerShell Profiles
    $profileEntries = Find-PowerShellProfiles
    if ($profileEntries.Count -gt 0) {
        Write-Host "🔍 Found $($profileEntries.Count) malicious PowerShell profiles" -ForegroundColor Red
        Remove-PowerShellProfiles -profiles $profileEntries
        $totalThreats += $profileEntries.Count
    }
    
    # BITS Jobs
    $bitsEntries = Find-MaliciousBITSJobs
    if ($bitsEntries.Count -gt 0) {
        Write-Host "🔍 Found $($bitsEntries.Count) malicious BITS jobs" -ForegroundColor Red
        Remove-BITSJobs -jobs $bitsEntries
        $totalThreats += $bitsEntries.Count
    }
    
    # IFEO Hijacking
    $ifeoEntries = Find-IFEOHijacks
    if ($ifeoEntries.Count -gt 0) {
        Write-Host "🔍 Found $($ifeoEntries.Count) IFEO hijacks" -ForegroundColor Red
        Remove-IFEOHijacks -hijacks $ifeoEntries
        $totalThreats += $ifeoEntries.Count
    }
    
    # Winlogon Hijacks
    $winlogonEntries = Find-WinlogonHijacks
    if ($winlogonEntries.Count -gt 0) {
        Write-Host "🔍 Found $($winlogonEntries.Count) Winlogon hijacks" -ForegroundColor Red
        Remove-WinlogonHijacks -hijacks $winlogonEntries
        $totalThreats += $winlogonEntries.Count
    }
    
    # Live Processes
    $processes = Find-ProcessesReferencingTarget
    if ($processes.Count -gt 0) {
        Write-Host "🔍 Found $($processes.Count) suspicious processes" -ForegroundColor Red
        $processes | ForEach-Object { Write-Host "  PID $($_.ProcessId): $($_.Name)" -ForegroundColor Gray }
        Stop-MaliciousProcesses -procs $processes
        $totalThreats += $processes.Count
    }
    
    # Save report
    $report = @{
        Timestamp = Get-Date
        Host = $env:COMPUTERNAME
        TargetFile = $TargetFile
        TotalThreats = $totalThreats
        RunKeys = $runEntries
        Startup = $startupEntries
        ScheduledTasks = $taskEntries
        Services = $svcEntries
        WMI = $wmiEntries
        PowerShellProfiles = $profileEntries
        BITSJobs = $bitsEntries
        IFEOHijacks = $ifeoEntries
        WinlogonHijacks = $winlogonEntries
        Processes = $processes
        Log = $global:LogEntries
    }
    
    $reportPath = Join-Path $QuarantinePath "DefenderReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report | ConvertTo-Json -Depth 8 | Out-File -FilePath $reportPath -Force -Encoding UTF8
    
    Write-Host ""
    Write-Host "🏆 DEFENSE COMPLETE!" -ForegroundColor Green
    Write-Host "📊 Total threats eliminated: $totalThreats" -ForegroundColor Cyan
    
    # Choco-specific intelligence summary
    $chocoThreats = 0
    if ($runEntries | Where-Object { $_.Path -imatch 'HKLM|HKCU.*Run' }) { $chocoThreats++ }
    if ($startupEntries | Where-Object { $_.IsVBS -eq $true }) { $chocoThreats++ }
    if ($scheduledTasks | Where-Object { $_.TaskName -imatch 'startup|logon' }) { $chocoThreats++ }
    if ($ifeoEntries | Where-Object { $_.IsChocoTarget -eq $true }) { $chocoThreats++ }
    if ($wmiEntries | Where-Object { $_.IsChocoPattern -eq $true }) { $chocoThreats++ }
    
    if ($chocoThreats -gt 0) {
        Write-Host "🎯 Choco attack patterns detected: $chocoThreats/5 vectors" -ForegroundColor Red
        Write-Host "   Registry (35-40s): $(if ($runEntries) { '✅ BLOCKED' } else { '🟢 CLEAN' })" -ForegroundColor $(if ($runEntries) { 'Yellow' } else { 'Green' })
        Write-Host "   Startup VBS (50-55s): $(if ($startupEntries) { '✅ BLOCKED' } else { '🟢 CLEAN' })" -ForegroundColor $(if ($startupEntries) { 'Yellow' } else { 'Green' })
        Write-Host "   Scheduled Tasks (45s+60s): $(if ($scheduledTasks) { '✅ BLOCKED' } else { '🟢 CLEAN' })" -ForegroundColor $(if ($scheduledTasks) { 'Yellow' } else { 'Green' })
        Write-Host "   IFEO Hijacks: $(if ($ifeoEntries) { '✅ BLOCKED' } else { '🟢 CLEAN' })" -ForegroundColor $(if ($ifeoEntries) { 'Yellow' } else { 'Green' })
        Write-Host "   WMI Events (70s): $(if ($wmiEntries) { '✅ BLOCKED' } else { '🟢 CLEAN' })" -ForegroundColor $(if ($wmiEntries) { 'Yellow' } else { 'Green' })
    } else {
        Write-Host "🛡️ No Choco attack patterns detected - System secure!" -ForegroundColor Green
    }
    
    Write-Host "📁 Report saved: $reportPath" -ForegroundColor Gray
    Write-Host "🗂️ Quarantine: $QuarantinePath" -ForegroundColor Gray
    
    # Post to collector if specified
    if ($CollectorUrl) {
        Send-ReportWithRetry -Url $CollectorUrl -Body $report | Out-Null
    }
    
    # Install watchdog if requested
    if ($InstallWatchdog) {
        Install-Watchdog
    }
}

function Find-RunKeysReferencingTarget {
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    # Choco-specific patterns from Soroush's attack code
    $chocoPatterns = @(
        "SecurityHealthSystray_*",
        "MicrosoftEdgeAutoLaunch_*",
        "WindowsUpdateScan*",
        "SystemMaintenance*"
    )
    
    $found = @()
    foreach ($k in $keys) {
        try {
            $props = Get-ItemProperty -Path $k -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
                $val = $p.Value -as [string]
                $isChocoPattern = $false
                $isMalicious = $false
                
                # Check for our target file
                if ($val -and ($val -imatch [regex]::Escape($TargetFile) -or $val -imatch 'pwned\.txt')) {
                    $isMalicious = $true
                }
                
                # Check for Base64 encoded content (Choco signature)
                if ($val -and (Test-Base64Content -Content $val)) {
                    $isMalicious = $true
                }
                
                # Check for Choco's specific naming patterns
                foreach ($pattern in $chocoPatterns) {
                    if ($p.Name -like $pattern) {
                        $isChocoPattern = $true
                        $isMalicious = $true
                        break
                    }
                }
                
                # Check for Choco's timing patterns (35-40 second delays)
                if ($val -and ($val -imatch 'Start-Sleep\s+(3[5-9]|40)')) {
                    $isChocoPattern = $true
                    $isMalicious = $true
                }
                
                if ($isMalicious) {
                    $found += [pscustomobject]@{ 
                        Key = $k
                        Name = $p.Name
                        Value = $val
                        IsChocoPattern = $isChocoPattern
                    }
                }
            }
        } catch {}
    }
    return $found
}

function Remove-RunKeys {
    param([psobject[]]$entries)
    foreach ($e in $entries) {
        if ($AutoRemediate -or (Read-Host "Remove registry entry $($e.Key)\$($e.Name)? (Y/N)") -match '^[Yy]') {
            try {
                Remove-ItemProperty -Path $e.Key -Name $e.Name -ErrorAction Stop
                Log "Removed registry entry: $($e.Key)\$($e.Name)"
            } catch {
                Log "Failed to remove registry entry $($e.Key)\$($e.Name): $_" "ERROR"
            }
        }
    }
}

function Find-StartupItemsReferencingTarget {
    $folders = @(
        [Environment]::GetFolderPath("CommonStartup"),
        [Environment]::GetFolderPath("Startup")
    ) | Get-Unique
    $found = @()
    foreach ($f in $folders) {
        if (-not (Test-Path $f)) { continue }
        Get-ChildItem -Path $f -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $content = $null
            $isChocoPattern = $false
            
            try { $content = Get-Content -Path $_.FullName -ErrorAction SilentlyContinue -Raw } catch {}
            
            # Check for our target file
            if (($_.FullName -imatch [regex]::Escape($TargetFile)) -or ($_.FullName -imatch 'pwned\.txt')) {
                $isChocoPattern = $true
            }
            
            if ($content) {
                # Check content for our target
                if (($content -imatch [regex]::Escape($TargetFile)) -or ($content -imatch 'pwned\.txt') -or (Test-Base64Content -Content $content)) {
                    $isChocoPattern = $true
                }
                
                # Check for Choco's VBS patterns (hidden PowerShell with delays)
                if ($_.Extension -eq '.vbs' -and $content -imatch 'CreateObject.*WScript\.Shell.*powershell.*windowstyle.*hidden') {
                    $isChocoPattern = $true
                }
                
                # Check for Choco's specific VBS file names
                if ($_.Name -like 'WindowsDefender.vbs' -or $_.Name -like 'OfficeClickToRun.vbs') {
                    $isChocoPattern = $true
                }
                
                # Check for 50-55 second delays (Choco's startup timing)
                if ($content -imatch 'Start-Sleep\s+(5[0-5])') {
                    $isChocoPattern = $true
                }
            }
            
            if ($isChocoPattern) {
                $found += [pscustomobject]@{ 
                    Folder = $f
                    File = $_.FullName
                    IsVBS = ($_.Extension -eq '.vbs')
                    IsChocoPattern = $true
                }
            }
        }
    }
    return $found
}

function Remove-StartupItems {
    param([psobject[]]$items)
    foreach ($i in $items) {
        if ($AutoRemediate -or (Read-Host "Remove startup file $($i.File)? (Y/N)") -match '^[Yy]') {
            Backup-FileToQuarantine -FilePath $i.File | Out-Null
            try {
                Remove-Item -Path $i.File -Force -ErrorAction Stop
                Log "Removed startup file $($i.File)"
            } catch {
                Log "Failed to remove startup file $($i.File): $_" "ERROR"
            }
        }
    }
}

function Find-ScheduledTasksReferencingTarget {
    $found = @()
    
    # Choco-specific task name patterns from Soroush's code
    $chocoTaskPatterns = @(
        "WindowsUpdateScan*",
        "SystemMaintenance*",
        "SystemEventMonitor_*",
        "SystemEventConsumer_*"
    )
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($t in $tasks) {
            $actionTexts = @()
            $isChocoPattern = $false
            $isMalicious = $false
            
            # Check for Choco's specific task naming patterns
            foreach ($pattern in $chocoTaskPatterns) {
                if ($t.TaskName -like $pattern) {
                    $isChocoPattern = $true
                    $isMalicious = $true
                    break
                }
            }
            
            foreach ($a in $t.Actions) {
                $actionTexts += ($a.Execute + " " + ($a.Arguments -join " "))
            }
            $joined = $actionTexts -join " ; "
            
            # Check for our target file
            if (($joined -imatch [regex]::Escape($TargetFile)) -or ($joined -imatch 'pwned\.txt')) {
                $isMalicious = $true
            }
            
            # Check for Base64 encoded content (Choco signature)
            if (Test-Base64Content -Content $joined) {
                $isMalicious = $true
            }
            
            # Check for Choco's specific timing patterns (45s and 60s delays)
            if ($joined -imatch 'Start-Sleep\s+(4[5-9]|5[0-9]|60)') {
                $isChocoPattern = $true
                $isMalicious = $true
            }
            
            # Check for Choco's trigger patterns (PT45S, PT60S delays)
            if ($t.Triggers) {
                foreach ($trigger in $t.Triggers) {
                    if ($trigger.Delay -and ($trigger.Delay -match 'PT(45|60)S')) {
                        $isChocoPattern = $true
                        $isMalicious = $true
                    }
                }
            }
            
            if ($isMalicious) {
                $found += [pscustomobject]@{
                    TaskPath = $t.TaskPath
                    TaskName = $t.TaskName
                    Actions = $joined
                    IsChocoPattern = $isChocoPattern
                }
            }
        }
    } catch {
        Log "Failed to enumerate scheduled tasks: $_" "ERROR"
    }
    return $found
}

function Remove-ScheduledTasks {
    param([psobject[]]$tasks)
    foreach ($t in $tasks) {
        if ($AutoRemediate -or (Read-Host "Remove scheduled task $($t.TaskName)? (Y/N)") -match '^[Yy]') {
            try {
                Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
                Log "Removed scheduled task: $($t.TaskPath)$($t.TaskName)"
            } catch {
                Log "Failed to remove scheduled task $($t.TaskName): $_" "ERROR"
            }
        }
    }
}

function Find-ServicesReferencingTarget {
    $found = @()
    try {
        $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
        foreach ($s in $svcs) {
            $p = $s.PathName -as [string]
            if ($p -and (($p -imatch [regex]::Escape($TargetFile)) -or ($p -imatch 'pwned\.txt'))) {
                $found += [pscustomobject]@{ Name=$s.Name; DisplayName=$s.DisplayName; PathName=$p }
            }
        }
    } catch {
        Log "Failed to enumerate services: $_" "ERROR"
    }
    return $found
}

function Remove-Services {
    param([psobject[]]$services)
    foreach ($svc in $services) {
        if ($AutoRemediate -or (Read-Host "Remove service $($svc.Name)? (Y/N)") -match '^[Yy]') {
            try {
                $svcObj = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
                if ($svcObj) {
                    $svcObj | Invoke-CimMethod -MethodName Delete | Out-Null
                    Log "Deleted service $($svc.Name)"
                }
            } catch {
                Log "Failed to delete service $($svc.Name): $_" "ERROR"
            }
        }
    }
}

function Find-WMISubscriptionsReferencingTarget {
    $found = @()
    try {
        # Check event consumers (Choco's WMI attack vector)
        $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop
        foreach ($c in $consumers) {
            $isChocoPattern = $false
            
            if ($c.PSObject.Properties.Match("CommandLine")) {
                # Check for our target file
                if (($c.CommandLine -imatch [regex]::Escape($TargetFile)) -or ($c.CommandLine -imatch 'pwned\.txt')) {
                    $isChocoPattern = $true
                }
                
                # Check for Base64 encoded content (common in Choco)
                if (Test-Base64Content -Content $c.CommandLine) {
                    $isChocoPattern = $true
                }
                
                # Check for PowerShell with delays (Choco's 70-second pattern)
                if ($c.CommandLine -imatch 'powershell.*sleep|powershell.*start-sleep|timeout.*70') {
                    $isChocoPattern = $true
                }
                
                if ($isChocoPattern) {
                    $found += [pscustomobject]@{ 
                        Consumer = $c.__RELPATH
                        Type = $c.__CLASS
                        Property = "CommandLine"
                        Value = $c.CommandLine
                        IsChocoPattern = $true
                    }
                }
            }
        }
        
        # Also check for Choco's specific event filters and consumers
        $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        foreach ($f in $filters) {
            $isChocoPattern = $false
            
            # Check for Choco's specific filter names
            if ($f.Name -and ($f.Name -like 'SystemEventMonitor_*')) {
                $isChocoPattern = $true
            }
            
            # Check for Choco's specific query pattern (WITHIN 60, Win32_LogicalDisk, DeviceID='C:')
            if ($f.Query -and ($f.Query -imatch 'WITHIN\s+60.*Win32_LogicalDisk.*DeviceID.*C:')) {
                $isChocoPattern = $true
            }
            
            if ($isChocoPattern) {
                $found += [pscustomobject]@{ 
                    Consumer = $f.__RELPATH
                    Type = $f.__CLASS
                    Property = "Query"
                    Value = $f.Query
                    IsChocoPattern = $true
                }
            }
        }
    } catch {
        Log "Failed to enumerate WMI subscriptions: $_" "ERROR"
    }
    return $found
}

function Remove-WMISubscriptions {
    param([psobject[]]$entries)
    foreach ($e in $entries) {
        if ($AutoRemediate -or (Read-Host "Remove WMI subscription $($e.Consumer)? (Y/N)") -match '^[Yy]') {
            try {
                $inst = Get-CimInstance -Namespace root\subscription -Query "SELECT * FROM __EventConsumer WHERE __RELPATH='$($e.Consumer)'" -ErrorAction Stop
                if ($inst) {
                    $inst | Remove-CimInstance -ErrorAction Stop
                    Log "Removed WMI subscription $($e.Consumer)"
                }
            } catch {
                Log "Failed to remove WMI subscription $($e.Consumer): $_" "ERROR"
            }
        }
    }
}

function Find-ProcessesReferencingTarget {
    $found = @()
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $cmd = $p.CommandLine -as [string]
            if ($cmd -and (($cmd -imatch [regex]::Escape($TargetFile)) -or ($cmd -imatch 'pwned\.txt') -or (Test-Base64Content -Content $cmd))) {
                try {
                    $owner = $p | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue
                    $ownerStr = if ($owner) { "$($owner.Domain)\$($owner.User)" } else { "N/A" }
                } catch { $ownerStr = "N/A" }
                $found += [pscustomobject]@{ ProcessId = $p.ProcessId; Name=$p.Name; CommandLine = $cmd; Owner=$ownerStr }
            }
        }
    } catch {
        Log "Failed to enumerate processes: $_" "ERROR"
    }
    return $found
}

function Find-PowerShellProfiles {
    $found = @()
    $profilePaths = @(
        $PROFILE.AllUsersAllHosts,
        $PROFILE.AllUsersCurrentHost,
        $PROFILE.CurrentUserAllHosts,
        $PROFILE.CurrentUserCurrentHost
    ) | Where-Object { $_ }
    
    foreach ($profilePath in $profilePaths) {
        if (Test-Path $profilePath) {
            try {
                $content = Get-Content -Path $profilePath -Raw -ErrorAction SilentlyContinue
                if ($content -and (($content -imatch [regex]::Escape($TargetFile)) -or ($content -imatch 'pwned\.txt') -or (Test-Base64Content -Content $content))) {
                    $found += [pscustomobject]@{ Path = $profilePath; Type = "PowerShell Profile" }
                }
            } catch {}
        }
    }
    return $found
}

function Remove-PowerShellProfiles {
    param([psobject[]]$profiles)
    foreach ($profile in $profiles) {
        if ($AutoRemediate -or (Read-Host "Remove malicious PowerShell profile $($profile.Path)? (Y/N)") -match '^[Yy]') {
            Backup-FileToQuarantine -FilePath $profile.Path | Out-Null
            try {
                Remove-Item -Path $profile.Path -Force -ErrorAction Stop
                Log "Removed PowerShell profile: $($profile.Path)"
            } catch {
                Log "Failed to remove PowerShell profile $($profile.Path): $_" "ERROR"
            }
        }
    }
}

function Find-MaliciousBITSJobs {
    $found = @()
    try {
        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
        foreach ($job in $bitsJobs) {
            $checkFields = @($job.DisplayName, $job.Description, $job.RemoteUrl, $job.LocalFile) -join " "
            if ($checkFields -imatch [regex]::Escape($TargetFile) -or $checkFields -imatch 'pwned\.txt') {
                $found += [pscustomobject]@{ 
                    JobId = $job.JobId
                    DisplayName = $job.DisplayName
                    State = $job.JobState
                    RemoteUrl = $job.RemoteUrl
                    LocalFile = $job.LocalFile
                }
            }
        }
    } catch {
        Log "Failed to enumerate BITS jobs: $_" "ERROR"
    }
    return $found
}

function Remove-BITSJobs {
    param([psobject[]]$jobs)
    foreach ($job in $jobs) {
        if ($AutoRemediate -or (Read-Host "Remove BITS job $($job.DisplayName)? (Y/N)") -match '^[Yy]') {
            try {
                Remove-BitsTransfer -BitsJob (Get-BitsTransfer -JobId $job.JobId) -ErrorAction Stop
                Log "Removed BITS job: $($job.DisplayName)"
            } catch {
                Log "Failed to remove BITS job $($job.JobId): $_" "ERROR"
            }
        }
    }
}

function Find-IFEOHijacks {
    $found = @()
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    
    # Choco's specific targets from Soroush's code
    $chocoTargets = @("notepad.exe", "write.exe", "cmd.exe", "mspaint.exe", "calc.exe", "regedit.exe", "powershell.exe", "explorer.exe")
    
    try {
        $subKeys = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue
        foreach ($key in $subKeys) {
            try {
                $debugger = Get-ItemProperty -Path $key.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
                if ($debugger -and $debugger.Debugger) {
                    $isChocoTarget = $false
                    $isMalicious = $false
                    
                    # Check if targeting our pwned file
                    if (($debugger.Debugger -imatch [regex]::Escape($TargetFile)) -or ($debugger.Debugger -imatch 'pwned\.txt')) {
                        $isMalicious = $true
                    }
                    
                    # Check for Base64 encoded content (Choco signature)
                    if (Test-Base64Content -Content $debugger.Debugger) {
                        $isMalicious = $true
                    }
                    
                    # Check if targeting Choco's specific executables
                    if ($key.PSChildName -in $chocoTargets) {
                        $isChocoTarget = $true
                        $isMalicious = $true
                    }
                    
                    # Check for Choco's 30-second delay pattern
                    if ($debugger.Debugger -imatch 'Start-Sleep\s+30') {
                        $isChocoTarget = $true
                        $isMalicious = $true
                    }
                    
                    if ($isMalicious) {
                        $found += [pscustomobject]@{
                            Executable = $key.PSChildName
                            Debugger = $debugger.Debugger
                            Path = $key.PSPath
                            IsChocoTarget = $isChocoTarget
                        }
                    }
                }
            } catch {}
        }
    } catch {
        Log "Failed to enumerate IFEO entries: $_" "ERROR"
    }
    return $found
}

function Remove-IFEOHijacks {
    param([psobject[]]$hijacks)
    foreach ($hijack in $hijacks) {
        if ($AutoRemediate -or (Read-Host "Remove IFEO hijack for $($hijack.Executable)? (Y/N)") -match '^[Yy]') {
            try {
                Remove-ItemProperty -Path $hijack.Path -Name "Debugger" -ErrorAction Stop
                Log "Removed IFEO hijack: $($hijack.Executable)"
            } catch {
                Log "Failed to remove IFEO hijack for $($hijack.Executable): $_" "ERROR"
            }
        }
    }
}

function Find-WinlogonHijacks {
    $found = @()
    $winlogonKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    
    foreach ($keyPath in $winlogonKeys) {
        try {
            $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            foreach ($propName in @("Shell", "Userinit")) {
                if ($props.$propName) {
                    $value = $props.$propName -as [string]
                    if ($value -and (($value -imatch [regex]::Escape($TargetFile)) -or ($value -imatch 'pwned\.txt'))) {
                        $found += [pscustomobject]@{
                            Key = $keyPath
                            Property = $propName
                            Value = $value
                        }
                    }
                }
            }
        } catch {}
    }
    return $found
}

function Remove-WinlogonHijacks {
    param([psobject[]]$hijacks)
    foreach ($hijack in $hijacks) {
        if ($AutoRemediate -or (Read-Host "Reset Winlogon $($hijack.Property) in $($hijack.Key)? (Y/N)") -match '^[Yy]') {
            try {
                # Reset to default values
                $defaultValues = @{
                    "Shell" = "explorer.exe"
                    "Userinit" = "C:\Windows\system32\userinit.exe,"
                }
                if ($defaultValues[$hijack.Property]) {
                    Set-ItemProperty -Path $hijack.Key -Name $hijack.Property -Value $defaultValues[$hijack.Property] -ErrorAction Stop
                    Log "Reset Winlogon $($hijack.Property) to default"
                }
            } catch {
                Log "Failed to reset Winlogon $($hijack.Property): $_" "ERROR"
            }
        }
    }
}

function Stop-MaliciousProcesses {
    param([psobject[]]$procs)
    foreach ($p in $procs) {
        if ($AutoRemediate -or (Read-Host "Terminate process $($p.Name) (PID $($p.ProcessId))? (Y/N)") -match '^[Yy]') {
            try {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
                Log "Terminated process $($p.ProcessId)"
            } catch {
                Log "Failed to terminate process $($p.ProcessId): $_" "ERROR"
            }
        }
    }
}

function Install-Watchdog {
    Write-Host "🛡️ Installing persistent watchdog protection..." -ForegroundColor Yellow
    
    $watchdogScript = @"
# Persistent Showdog Watchdog
`$targetFile = "$TargetFile"
if (Test-Path `$targetFile) {
    Remove-Item `$targetFile -Force -ErrorAction SilentlyContinue
    Write-EventLog -LogName Application -Source "PersistentShowdown" -EventId 1001 -Message "Watchdog removed malware file: `$targetFile" -ErrorAction SilentlyContinue
}
"@
    
    $watchdogPath = "C:\ProgramData\PersistentShowdown\watchdog.ps1"
    New-Directory -Path (Split-Path $watchdogPath)
    $watchdogScript | Out-File -FilePath $watchdogPath -Force
    
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$watchdogPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName "PersistentShowdown_Watchdog" -Action $action -Trigger $trigger -Principal $principal -Description "Persistent protection against malware recreation" -Force
        Log "Installed watchdog scheduled task"
        Write-Host "✅ Watchdog installed successfully!" -ForegroundColor Green
    } catch {
        Log "Failed to install watchdog: $_" "ERROR"
        Write-Host "❌ Failed to install watchdog" -ForegroundColor Red
    }
}

function Send-ReportWithRetry {
    param([string]$Url, [object]$Body, [int]$MaxAttempts = 3)
    if (-not $Url) { return $false }
    
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Invoke-RestMethod -Uri $Url -Method Post -Body ($Body | ConvertTo-Json -Depth 8) -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
            Log "Posted report to collector on attempt $attempt"
            return $true
        } catch {
            Log "Failed to post report (attempt $attempt): $_" "WARN"
            if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds 2 }
        }
    }
    return $false
}

#endregion

#region Attacker Functions

function Start-AttackerMode {
    Write-Banner "🔴 EDUCATIONAL MALWARE SIMULATOR" "Red"
    
    Write-Host "⚠️ Educational Purpose Only - Use in isolated test environments" -ForegroundColor Yellow
    Write-Host ""
    
    switch ($Action) {
        "Install" { Install-PersistenceMechanisms }
        "Payload" { Invoke-PayloadExecution }
        "Cleanup" { Remove-PersistenceMechanisms }
    }
}

function Install-PersistenceMechanisms {
    Write-Host "🔴 Installing educational malware persistence mechanisms..." -ForegroundColor Red
    Write-Host "Target file: $TargetFile" -ForegroundColor Yellow
    
    $installed = @()
    
    # Create target file
    New-Directory -Path (Split-Path $TargetFile)
    "PWNED! Educational malware installed at $(Get-Date)" | Out-File -FilePath $TargetFile -Force
    $installed += "Target file: $TargetFile"
    
    # Registry Run Key
    try {
        $regKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $regKey -Name "EducationalMalware" -Value "powershell.exe -WindowStyle Hidden -Command `"'PWNED from registry!' | Out-File '$TargetFile' -Append`"" -Force
        $installed += "Registry Run Key: $regKey\EducationalMalware"
        Log "Installed registry persistence"
    } catch {
        Log "Failed to install registry persistence: $_" "ERROR"
    }
    
    # Startup Folder
    try {
        $startupPath = [Environment]::GetFolderPath("Startup")
        $startupFile = Join-Path $startupPath "educational_malware.bat"
        "@echo off`necho PWNED from startup! >> `"$TargetFile`"" | Out-File -FilePath $startupFile -Force -Encoding ASCII
        $installed += "Startup file: $startupFile"
        Log "Installed startup persistence"
    } catch {
        Log "Failed to install startup persistence: $_" "ERROR"
    }
    
    # Scheduled Task
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"'PWNED from task!' | Out-File '$TargetFile' -Append`""
        $trigger = New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -TaskName "EducationalMalware" -Action $action -Trigger $trigger -Description "Educational malware demo" -Force
        $installed += "Scheduled Task: EducationalMalware"
        Log "Installed scheduled task persistence"
    } catch {
        Log "Failed to install scheduled task persistence: $_" "ERROR"
    }
    
    Write-Host ""
    Write-Host "🔴 Educational malware installed!" -ForegroundColor Red
    Write-Host "📊 Persistence mechanisms created:" -ForegroundColor Yellow
    $installed | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host ""
    Write-Host "🛡️ Now run the defender to test detection!" -ForegroundColor Green
}

function Invoke-PayloadExecution {
    Write-Host "🔴 Executing educational malware payload..." -ForegroundColor Red
    New-Directory -Path (Split-Path $TargetFile)
    "PWNED! Payload executed at $(Get-Date)" | Out-File -FilePath $TargetFile -Force
    Write-Host "✅ Payload executed: $TargetFile" -ForegroundColor Yellow
}

function Remove-PersistenceMechanisms {
    Write-Host "🧹 Cleaning up educational malware..." -ForegroundColor Yellow
    
    $cleaned = @()
    
    # Remove target file
    if (Test-Path $TargetFile) {
        Remove-Item -Path $TargetFile -Force -ErrorAction SilentlyContinue
        $cleaned += "Target file: $TargetFile"
    }
    
    # Remove registry entry
    try {
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EducationalMalware" -ErrorAction SilentlyContinue
        $cleaned += "Registry entry removed"
    } catch {}
    
    # Remove startup file
    $startupFile = Join-Path ([Environment]::GetFolderPath("Startup")) "educational_malware.bat"
    if (Test-Path $startupFile) {
        Remove-Item -Path $startupFile -Force -ErrorAction SilentlyContinue
        $cleaned += "Startup file: $startupFile"
    }
    
    # Remove scheduled task
    try {
        Unregister-ScheduledTask -TaskName "EducationalMalware" -Confirm:$false -ErrorAction SilentlyContinue
        $cleaned += "Scheduled task removed"
    } catch {}
    
    Write-Host "✅ Cleanup complete!" -ForegroundColor Green
    $cleaned | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

#endregion

#region Competition Functions

function Start-CompetitionMode {
    Write-Banner "🏆 PERSISTENT SHOWDOWN COMPETITION" "Magenta"
    
    Write-Host "Automated competition: Attacker vs Defender" -ForegroundColor Yellow
    Write-Host ""
    
    $startTime = Get-Date
    
    # Phase 1: Setup
    Write-Host "⏱️ Phase 1: Environment Setup" -ForegroundColor Cyan
    Install-PersistenceMechanisms
    Start-Sleep -Seconds 3
    
    # Phase 2: Attack
    Write-Host "⏱️ Phase 2: Attack Phase" -ForegroundColor Red
    Invoke-PayloadExecution
    Start-Sleep -Seconds 2
    
    # Verify attack success
    $attackSuccess = Test-Path $TargetFile
    Write-Host "📊 Attack Success: $attackSuccess" -ForegroundColor $(if ($attackSuccess) {"Red"} else {"Green"})
    
    # Phase 3: Defense
    Write-Host "⏱️ Phase 3: Defense Phase" -ForegroundColor Green
    $script:AutoRemediate = $true
    Start-DefenderMode
    
    # Phase 4: Verification
    Write-Host "⏱️ Phase 4: Verification" -ForegroundColor Blue
    $defenseSuccess = -not (Test-Path $TargetFile)
    
    # Calculate results
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host ""
        Write-Banner "🏆 COMPETITION RESULTS" "Magenta"
    Write-Host "🔴 Attack Success: $attackSuccess" -ForegroundColor $(if ($attackSuccess) {"Red"} else {"Green"})
    Write-Host "🛡️ Defense Success: $defenseSuccess" -ForegroundColor $(if ($defenseSuccess) {"Green"} else {"Red"})
    Write-Host "⏱️ Total Duration: $($duration.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Cyan
    Write-Host ""
    
    $winner = if ($defenseSuccess) { "🛡️ DEFENDER WINS!" } else { "🔴 ATTACKER WINS!" }
    $winnerColor = if ($defenseSuccess) { "Green" } else { "Red" }
    Write-Host $winner -ForegroundColor $winnerColor
}

#endregion

#region Test Functions

function Start-TestMode {
    Write-Banner "🧪 COMPREHENSIVE TESTING FRAMEWORK" "Yellow"
    
    Write-Host "Running comprehensive tests..." -ForegroundColor Yellow
    Write-Host ""
    
    # Test 1: Basic Functionality
    Write-Host "Test 1: Basic target file creation and removal" -ForegroundColor Cyan
    Invoke-PayloadExecution
    $test1Pass = Test-Path $TargetFile
    if (Test-Path $TargetFile) { Remove-Item $TargetFile -Force }
    $test1CleanPass = -not (Test-Path $TargetFile)
    Write-Host "  File creation: $(if ($test1Pass) {"✅ PASS"} else {"❌ FAIL"})" -ForegroundColor $(if ($test1Pass) {"Green"} else {"Red"})
    Write-Host "  File removal: $(if ($test1CleanPass) {"✅ PASS"} else {"❌ FAIL"})" -ForegroundColor $(if ($test1CleanPass) {"Green"} else {"Red"})
    
    # Test 2: Registry Persistence
    Write-Host "Test 2: Registry persistence detection" -ForegroundColor Cyan
    try {
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "TestMalware" -Value "test_command_with_pwned.txt" -Force
        $regEntries = Find-RunKeysReferencingTarget
        $test2Pass = $regEntries.Count -gt 0
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "TestMalware" -ErrorAction SilentlyContinue
        Write-Host "  Registry detection: $(if ($test2Pass) {"✅ PASS"} else {"❌ FAIL"})" -ForegroundColor $(if ($test2Pass) {"Green"} else {"Red"})
    } catch {
        Write-Host "  Registry detection: ❌ FAIL (Error: $_)" -ForegroundColor Red
    }
    
    # Test 3: Startup Detection
    Write-Host "Test 3: Startup folder detection" -ForegroundColor Cyan
    try {
        $testStartupFile = Join-Path ([Environment]::GetFolderPath("Startup")) "test_pwned.bat"
        "echo test with pwned.txt" | Out-File -FilePath $testStartupFile -Force
        $startupEntries = Find-StartupItemsReferencingTarget
        $test3Pass = $startupEntries.Count -gt 0
        Remove-Item $testStartupFile -Force -ErrorAction SilentlyContinue
        Write-Host "  Startup detection: $(if ($test3Pass) {"✅ PASS"} else {"❌ FAIL"})" -ForegroundColor $(if ($test3Pass) {"Green"} else {"Red"})
    } catch {
        Write-Host "  Startup detection: ❌ FAIL (Error: $_)" -ForegroundColor Red
    }
    
    # Test 4: Process Detection
    Write-Host "Test 4: Process detection" -ForegroundColor Cyan
    # This test would require actually running a process, which might be risky
    Write-Host "  Process detection: ⚠️ SKIP (Requires live process)" -ForegroundColor Yellow
    
    # Test 5: Quarantine System
    Write-Host "Test 5: Quarantine system" -ForegroundColor Cyan
    $testFile = "C:\temp\test_quarantine.txt"
    try {
        New-Directory -Path "C:\temp"
        "test content" | Out-File -FilePath $testFile -Force
        $quarantined = Backup-FileToQuarantine -FilePath $testFile
        $test5Pass = $quarantined -and (Test-Path $quarantined)
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        Write-Host "  Quarantine system: $(if ($test5Pass) {"✅ PASS"} else {"❌ FAIL"})" -ForegroundColor $(if ($test5Pass) {"Green"} else {"Red"})
    } catch {
        Write-Host "  Quarantine system: ❌ FAIL (Error: $_)" -ForegroundColor Red
    }
    
    $passedTests = @($test1Pass, $test1CleanPass, $test2Pass, $test3Pass, $test5Pass) | Where-Object { $_ -eq $true }
    $totalTests = 5
    
    Write-Host ""
    Write-Host "📊 Test Results: $($passedTests.Count)/$totalTests passed" -ForegroundColor $(if ($passedTests.Count -eq $totalTests) {"Green"} else {"Yellow"})
    
    if ($passedTests.Count -eq $totalTests) {
        Write-Host "🏆 ALL TESTS PASSED!" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Some tests failed - check implementation" -ForegroundColor Yellow
    }
}

#endregion

#region Deploy Functions

function Start-DeployMode {
    Write-Banner "🚀 DEPLOYMENT ENVIRONMENT CREATOR" "Cyan"
    
    Write-Host "Creating deployment environment..." -ForegroundColor Yellow
    
    # Create directory structure
    $deployDir = "C:\PersistentShowdown_Deploy"
    $dirs = @(
        $deployDir,
        "$deployDir\Scripts",
        "$deployDir\Logs",
        "$deployDir\Reports",
        "$deployDir\Quarantine"
    )
    
    foreach ($dir in $dirs) {
        New-Directory -Path $dir
        Write-Host "✅ Created: $dir" -ForegroundColor Green
    }
    
    # Copy this script to deployment directory
    $thisScript = $MyInvocation.MyCommand.Path
    if ($thisScript) {
        Copy-Item -Path $thisScript -Destination "$deployDir\Scripts\PersistentShowdown_AllInOne.ps1" -Force
        Write-Host "✅ Copied main script to deployment" -ForegroundColor Green
    }
    
    # Create quick launcher scripts
    $launcherScripts = @{
        "Run_Defender.bat" = "@echo off`npowershell.exe -ExecutionPolicy Bypass -File `"Scripts\PersistentShowdown_AllInOne.ps1`" -Mode Defender -AutoRemediate`npause"
        "Run_Competition.bat" = "@echo off`npowershell.exe -ExecutionPolicy Bypass -File `"Scripts\PersistentShowdown_AllInOne.ps1`" -Mode Competition`npause"
        "Run_Tests.bat" = "@echo off`npowershell.exe -ExecutionPolicy Bypass -File `"Scripts\PersistentShowdown_AllInOne.ps1`" -Mode Test`npause"
        "Install_Malware.bat" = "@echo off`necho WARNING: Educational malware installation`necho Press Ctrl+C to cancel, or`npause`npowershell.exe -ExecutionPolicy Bypass -File `"Scripts\PersistentShowdown_AllInOne.ps1`" -Mode Attacker -Action Install`npause"
    }
    
    foreach ($script in $launcherScripts.GetEnumerator()) {
        $scriptPath = Join-Path $deployDir $script.Key
        $script.Value | Out-File -FilePath $scriptPath -Force -Encoding ASCII
        Write-Host "✅ Created launcher: $($script.Key)" -ForegroundColor Green
    }
    
    # Create README
    $readme = @"
# PERSISTENT SHOWDOWN - DEPLOYMENT PACKAGE

## Quick Start

### For Administrators:
- Double-click `Run_Defender.bat` to start defender in auto mode
- Double-click `Run_Competition.bat` for full attacker vs defender demo
- Double-click `Run_Tests.bat` to run comprehensive tests

### For Advanced Users:
- Use PowerShell: `.\Scripts\PersistentShowdown_AllInOne.ps1 -Mode Menu`
- See PowerShell help: `Get-Help .\Scripts\PersistentShowdown_AllInOne.ps1 -Full`

## Directory Structure:
- `Scripts\` - Main PowerShell script
- `Logs\` - Execution logs
- `Reports\` - JSON reports from defender
- `Quarantine\` - Quarantined malware files

## Safety:
- Educational use only
- Test in isolated environments
- All "malware" is simulated and harmless

Created: $(Get-Date)
"@
    
    $readme | Out-File -FilePath "$deployDir\README.txt" -Force
    Write-Host "✅ Created README.txt" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "🏆 DEPLOYMENT COMPLETE!" -ForegroundColor Green
    Write-Host "📁 Location: $deployDir" -ForegroundColor Cyan
    Write-Host "🚀 Ready for distribution!" -ForegroundColor Yellow
    
    # Open deployment directory
    try {
        Start-Process explorer.exe -ArgumentList $deployDir
    } catch {}
}

#endregion

#region WebServer Functions

function Start-WebServerMode {
    Write-Banner "🌐 HTTP DEPLOYMENT SERVER" "White"
    
    Write-Host "Starting HTTP server for remote deployment..." -ForegroundColor Yellow
    Write-Host "Port: $ServerPort" -ForegroundColor Cyan
    
    try {
        # Get local IP
        $localIP = (Get-NetIPConfiguration | Where-Object {$null -ne $_.IPv4DefaultGateway -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress | Select-Object -First 1
        if (-not $localIP) { $localIP = "127.0.0.1" }
        
        Write-Host "🌐 Server URL: http://$localIP`:$ServerPort" -ForegroundColor Green
        Write-Host ""
        Write-Host "📋 Available for download:" -ForegroundColor Yellow
        Write-Host "  - This script (all-in-one solution)" -ForegroundColor Gray
        Write-Host "  - Individual components" -ForegroundColor Gray
        Write-Host ""
        Write-Host "💡 On remote machine, use:" -ForegroundColor Cyan
        Write-Host "  Invoke-WebRequest http://$localIP`:$ServerPort/PersistentShowdown_AllInOne.ps1 -OutFile defender.ps1" -ForegroundColor White
        Write-Host ""
        Write-Host "Press Ctrl+C to stop server" -ForegroundColor Yellow
        
        # Simple HTTP server implementation
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://+:$ServerPort/")
        $listener.Start()
        
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "[$timestamp] $($request.RemoteEndPoint.Address) - $($request.HttpMethod) $($request.Url.LocalPath)" -ForegroundColor Gray
            
            if ($request.Url.LocalPath -eq "/PersistentShowdown_AllInOne.ps1" -or $request.Url.LocalPath -eq "/") {
                # Serve this script
                $thisScript = $MyInvocation.MyCommand.Path
                if ($thisScript -and (Test-Path $thisScript)) {
                    $content = Get-Content -Path $thisScript -Raw -Encoding UTF8
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
                    
                    $response.ContentType = "text/plain"
                    $response.ContentLength64 = $bytes.Length
                    $response.Headers.Add("Content-Disposition", "attachment; filename=PersistentShowdown_AllInOne.ps1")
                    $response.OutputStream.Write($bytes, 0, $bytes.Length)
                } else {
                    $response.StatusCode = 404
                    $errorBytes = [System.Text.Encoding]::UTF8.GetBytes("Script file not found")
                    $response.OutputStream.Write($errorBytes, 0, $errorBytes.Length)
                }
            } else {
                # Serve directory listing
                $html = @"
<!DOCTYPE html>
<html>
<head><title>Persistent Showdown - Deployment Server</title></head>
<body>
<h1>🏆 Persistent Showdown - Deployment Server</h1>
<h2>📦 Available Downloads:</h2>
<ul>
<li><a href="/PersistentShowdown_AllInOne.ps1">PersistentShowdown_AllInOne.ps1</a> - Complete solution in one file</li>
</ul>
<h2>💡 Usage:</h2>
<pre>
# Download to Windows machine:
Invoke-WebRequest http://$localIP`:$ServerPort/PersistentShowdown_AllInOne.ps1 -OutFile defender.ps1

# Run defender:
.\defender.ps1 -Mode Defender -AutoRemediate

# Run full competition:
.\defender.ps1 -Mode Competition

# Interactive menu:
.\defender.ps1 -Mode Menu
</pre>
</body>
</html>
"@
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentType = "text/html"
                $response.ContentLength64 = $bytes.Length
                $response.OutputStream.Write($bytes, 0, $bytes.Length)
            }
            
            $response.Close()
        }
    } catch {
        if ($_.Exception.Message -like "*interrupted*" -or $_.Exception.Message -like "*aborted*") {
            Write-Host "`n🛑 Server stopped" -ForegroundColor Yellow
        } else {
            Write-Host "❌ Server error: $_" -ForegroundColor Red
        }
    } finally {
        if ($listener -and $listener.IsListening) {
            $listener.Stop()
        }
    }
}

#endregion

#region Real-Time Protection Functions

function Start-RealTimeProtection {
    Write-Banner "🛡️ REAL-TIME PROTECTION SYSTEM" "Green"
    
    Write-Host "🚀 Initializing active defense system..." -ForegroundColor Yellow
    Write-Host "🎯 Target protection: $TargetFile" -ForegroundColor Cyan
    Write-Host "🔬 Choco Intelligence: ACTIVE - Enhanced with Soroush's attack patterns" -ForegroundColor Yellow
    Write-Host "⏱️ Attack timeline: IFEO (30s), Registry (35-40s), Tasks (45-60s), Startup (50-55s), WMI (70s)" -ForegroundColor Gray
    Write-Host "🎲 Detection patterns: WindowsUpdateScan*, SecurityHealthSystray*, MicrosoftEdgeAutoLaunch*" -ForegroundColor Gray
    Write-Host "⚡ Real-time monitoring: ACTIVE" -ForegroundColor Green
    Write-Host "🔄 Auto-remediation: ENABLED" -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 This system will actively block all 5 Choco attack vectors as they happen!" -ForegroundColor Yellow
    Write-Host "💡 Press Ctrl+C to stop protection" -ForegroundColor Gray
    Write-Host ""
    
    # Initialize protection state
    $global:ProtectionActive = $true
    $global:ThreatCount = 0
    $global:BlockedAttacks = @()
    
    # Install file system watcher
    Start-FileSystemWatcher
    
    # Install registry monitor
    Start-RegistryMonitor
    
    # Install process monitor
    Start-ProcessMonitor
    
    # Main protection loop
    try {
        Write-Host "🛡️ PROTECTION ACTIVE - Monitoring for threats..." -ForegroundColor Green
        while ($global:ProtectionActive) {
            Start-Sleep -Seconds 2
            
            # Quick scan for immediate threats
            Invoke-QuickThreatScan
            
            # Update status
            $timestamp = Get-Date -Format "HH:mm:ss"
            Write-Host "`r[$timestamp] 🛡️ Protected | Threats Blocked: $global:ThreatCount" -NoNewline -ForegroundColor Green
        }
    } catch {
        Write-Host "`n❌ Protection interrupted: $_" -ForegroundColor Red
    } finally {
        Stop-RealTimeProtection
    }
}

function Start-FileSystemWatcher {
    try {
        $global:FileWatcher = New-Object System.IO.FileSystemWatcher
        $global:FileWatcher.Path = Split-Path $TargetFile
        $global:FileWatcher.Filter = [System.IO.Path]::GetFileName($TargetFile)
        $global:FileWatcher.EnableRaisingEvents = $true
        
        # Register event handler
        Register-ObjectEvent -InputObject $global:FileWatcher -EventName "Created" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            Write-Host "`n🚨 THREAT DETECTED: File creation attempt - $filePath" -ForegroundColor Red
            Write-Host "🛡️ BLOCKING: Removing malicious file immediately" -ForegroundColor Yellow
            
            try {
                Start-Sleep -Milliseconds 100  # Brief delay to ensure file is written
                Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
                $global:ThreatCount++
                $global:BlockedAttacks += "File Creation: $filePath at $(Get-Date)"
                Write-Host "✅ BLOCKED: Malicious file eliminated" -ForegroundColor Green
                
                # Log the incident
                Log "REAL-TIME BLOCK: File creation $filePath" "SECURITY"
            } catch {
                Write-Host "⚠️ Warning: Could not remove file $filePath" -ForegroundColor Yellow
            }
        } | Out-Null
        
        Log "File system watcher activated for $TargetFile"
    } catch {
        Write-Host "⚠️ Warning: Could not initialize file system watcher: $_" -ForegroundColor Yellow
    }
}

function Start-RegistryMonitor {
    # Start background job to monitor registry changes
    $global:RegistryMonitorJob = Start-Job -ScriptBlock {
        param($TargetFile)
        
        $monitorKeys = @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        while ($true) {
            foreach ($key in $monitorKeys) {
                try {
                    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                    if ($props) {
                        foreach ($prop in $props.PSObject.Properties) {
                            if ($prop.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
                            $val = $prop.Value -as [string]
                            if ($val -and ($val -imatch [regex]::Escape($TargetFile) -or $val -imatch 'pwned\.txt')) {
                                # Threat detected - signal main thread
                                return @{
                                    Type = "Registry"
                                    Key = $key
                                    Name = $prop.Name
                                    Value = $val
                                    Timestamp = Get-Date
                                }
                            }
                        }
                    }
                } catch {}
            }
            Start-Sleep -Seconds 1
        }
    } -ArgumentList $TargetFile
    
    Log "Registry monitor activated"
}

function Start-ProcessMonitor {
    # Start background job to monitor processes
    $global:ProcessMonitorJob = Start-Job -ScriptBlock {
        param($TargetFile)
        
        while ($true) {
            try {
                $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
                foreach ($p in $procs) {
                    $cmd = $p.CommandLine -as [string]
                    if ($cmd -and (($cmd -imatch [regex]::Escape($TargetFile)) -or ($cmd -imatch 'pwned\.txt'))) {
                        return @{
                            Type = "Process"
                            ProcessId = $p.ProcessId
                            Name = $p.Name
                            CommandLine = $cmd
                            Timestamp = Get-Date
                        }
                    }
                }
            } catch {}
            Start-Sleep -Seconds 2
        }
    } -ArgumentList $TargetFile
    
    Log "Process monitor activated"
}

function Invoke-QuickThreatScan {
    # Check for registry threats
    if ($global:RegistryMonitorJob -and $global:RegistryMonitorJob.HasMoreData) {
        $threat = Receive-Job -Job $global:RegistryMonitorJob
        if ($threat) {
            Write-Host "`n🚨 THREAT DETECTED: Registry persistence - $($threat.Key)\$($threat.Name)" -ForegroundColor Red
            Write-Host "🛡️ BLOCKING: Removing malicious registry entry" -ForegroundColor Yellow
            
            try {
                Remove-ItemProperty -Path $threat.Key -Name $threat.Name -ErrorAction SilentlyContinue
                $global:ThreatCount++
                $global:BlockedAttacks += "Registry Entry: $($threat.Key)\$($threat.Name) at $($threat.Timestamp)"
                Write-Host "✅ BLOCKED: Registry threat eliminated" -ForegroundColor Green
                Log "REAL-TIME BLOCK: Registry entry $($threat.Key)\$($threat.Name)" "SECURITY"
            } catch {
                Write-Host "⚠️ Warning: Could not remove registry entry" -ForegroundColor Yellow
            }
        }
    }
    
    # Check for process threats
    if ($global:ProcessMonitorJob -and $global:ProcessMonitorJob.HasMoreData) {
        $threat = Receive-Job -Job $global:ProcessMonitorJob
        if ($threat) {
            Write-Host "`n🚨 THREAT DETECTED: Malicious process - PID $($threat.ProcessId)" -ForegroundColor Red
            Write-Host "🛡️ BLOCKING: Terminating malicious process" -ForegroundColor Yellow
            
            try {
                Stop-Process -Id $threat.ProcessId -Force -ErrorAction SilentlyContinue
                $global:ThreatCount++
                $global:BlockedAttacks += "Process: $($threat.Name) (PID $($threat.ProcessId)) at $($threat.Timestamp)"
                Write-Host "✅ BLOCKED: Malicious process terminated" -ForegroundColor Green
                Log "REAL-TIME BLOCK: Process $($threat.ProcessId) - $($threat.CommandLine)" "SECURITY"
            } catch {
                Write-Host "⚠️ Warning: Could not terminate process $($threat.ProcessId)" -ForegroundColor Yellow
            }
        }
    }
}

function Stop-RealTimeProtection {
    Write-Host "`n`n🛑 Stopping real-time protection..." -ForegroundColor Yellow
    
    $global:ProtectionActive = $false
    
    # Cleanup file watcher
    if ($global:FileWatcher) {
        $global:FileWatcher.EnableRaisingEvents = $false
        $global:FileWatcher.Dispose()
        Get-EventSubscriber | Unregister-Event
        Log "File system watcher stopped"
    }
    
    # Cleanup background jobs
    if ($global:RegistryMonitorJob) {
        Stop-Job -Job $global:RegistryMonitorJob -PassThru | Remove-Job
        Log "Registry monitor stopped"
    }
    
    if ($global:ProcessMonitorJob) {
        Stop-Job -Job $global:ProcessMonitorJob -PassThru | Remove-Job
        Log "Process monitor stopped"
    }
    
    # Show protection summary
    Write-Host ""
    Write-Banner "🛡️ PROTECTION SUMMARY" "Green"
    Write-Host "🎯 Total threats blocked: $global:ThreatCount" -ForegroundColor Cyan
    Write-Host "⏱️ Session duration: Active protection" -ForegroundColor Gray
    
    if ($global:BlockedAttacks.Count -gt 0) {
        Write-Host ""
        Write-Host "🚨 Blocked attacks:" -ForegroundColor Yellow
        $global:BlockedAttacks | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
    
    Write-Host ""
    Write-Host "🏆 SYSTEM PROTECTED!" -ForegroundColor Green
}

#endregion

#region AutoStart Protection Functions

function Install-AutoStartProtection {
    Write-Banner "⚡ AUTOMATIC STARTUP PROTECTION" "Magenta"
    
    Write-Host "🚀 Installing automatic protection system..." -ForegroundColor Yellow
    Write-Host "🎯 This will protect against Choco attacks automatically at startup" -ForegroundColor Cyan
    Write-Host ""
    
    # Check if running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "⚠️ Administrator privileges required for automatic protection" -ForegroundColor Yellow
        Write-Host "📋 Alternative: Manual protection available via option 8 (RealTime)" -ForegroundColor Gray
        Write-Host ""
        Read-Host "Press Enter to continue with manual instructions"
        Show-ManualProtectionInstructions
        return
    }
    
    try {
        # Create scheduled task for automatic protection
        $taskName = "PersistentShowdownProtection"
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) { $scriptPath = $MyInvocation.ScriptName }
        if (-not $scriptPath) { $scriptPath = (Get-Location).Path + "\PersistentShowdown_AllInOne.ps1" }
        
        Write-Host "📁 Script location: $scriptPath" -ForegroundColor Gray
        
        # Remove existing task if present
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        } catch {}
        
        # Create new task
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode RealTime -AutoRemediate"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
        
        Write-Host "✅ Automatic protection installed successfully!" -ForegroundColor Green
        Write-Host "🛡️ System will now automatically protect against Choco attacks" -ForegroundColor Green
        Write-Host "⚡ Protection starts at system boot" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "🔍 Task Details:" -ForegroundColor Gray
        Write-Host "   Name: $taskName" -ForegroundColor Gray
        Write-Host "   Trigger: At system startup" -ForegroundColor Gray
        Write-Host "   Mode: Hidden real-time protection" -ForegroundColor Gray
        Write-Host ""
        
        # Offer to start protection now
        $startNow = Read-Host "Start protection now? (Y/N)"
        if ($startNow -match '^[Yy]') {
            Write-Host "🚀 Starting protection immediately..." -ForegroundColor Green
            Start-RealTimeProtection
        }
        
    } catch {
        Write-Host "❌ Failed to install automatic protection: $_" -ForegroundColor Red
        Write-Host "📋 Falling back to manual protection instructions..." -ForegroundColor Yellow
        Show-ManualProtectionInstructions
    }
}

function Show-ManualProtectionInstructions {
    Write-Host ""
    Write-Banner "📋 MANUAL PROTECTION SETUP" "Yellow"
    
    Write-Host "🎯 For your colleagues to get automatic protection:" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Option 1: Run as Administrator and use AutoStart (Recommended)" -ForegroundColor Green
    Write-Host "   1. Right-click PowerShell and 'Run as Administrator'" -ForegroundColor Gray
    Write-Host "   2. Run: .\$($MyInvocation.MyCommand.Name) -Mode Menu" -ForegroundColor Gray
    Write-Host "   3. Select option 9 (AutoStart)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Option 2: Manual Real-Time Protection" -ForegroundColor Yellow
    Write-Host "   Run: .\$($MyInvocation.MyCommand.Name) -Mode RealTime" -ForegroundColor Gray
    Write-Host "   (Must stay running for protection)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Option 3: Create Desktop Shortcut" -ForegroundColor Cyan
    Write-Host "   Target: PowerShell.exe -ExecutionPolicy Bypass -File `"$($MyInvocation.ScriptName)`" -Mode RealTime" -ForegroundColor Gray
    Write-Host "   Name: Choco Protection" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "💡 The AutoStart option (requires admin) provides the best experience!" -ForegroundColor Yellow
}

function Remove-AutoStartProtection {
    Write-Host "🗑️ Removing automatic protection..." -ForegroundColor Yellow
    try {
        Unregister-ScheduledTask -TaskName "PersistentShowdownProtection" -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "✅ Automatic protection removed" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ No automatic protection found to remove" -ForegroundColor Gray
    }
}

#endregion

#region Main Entry Point

# Main execution logic
try {
    # Check for admin privileges (non-blocking)
    Assert-Admin
    
    # Execute based on mode
    switch ($Mode) {
        "Defender" { Start-DefenderMode }
        "Attacker" { Start-AttackerMode }
        "Watchdog" { 
            Write-Banner "👁️ WATCHDOG INSTALLATION" "Blue"
            Install-Watchdog 
        }
        "Competition" { Start-CompetitionMode }
        "Test" { Start-TestMode }
        "Deploy" { Start-DeployMode }
        "WebServer" { Start-WebServerMode }
        "RealTime" { Start-RealTimeProtection }
        "AutoStart" { Install-AutoStartProtection }
        "Menu" { Show-Menu }
        default { Show-Menu }
    }
    
} catch {
    Write-Host "❌ Unexpected error: $_" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Gray
} finally {
    if ($Mode -ne "WebServer") {
        Write-Host ""
        Write-Host "🏆 Persistent Showdown execution complete!" -ForegroundColor Green
        Write-Host "📧 For support or questions, contact the development team." -ForegroundColor Gray
    }
}

#endregion