param([switch]$Elevate, [string]$ReaderSid)
$ErrorActionPreference = 'Stop'
$destination = Join-Path $env:ProgramFiles 'VpnGuard'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$version = '0.2.0-preview'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
try {
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [version]'5.1' -or
        -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        throw 'Use Windows x64 and 64-bit Windows PowerShell 5.1. PowerShell 7 and ARM64 are not supported.'
    }
    if (-not $ReaderSid) { $ReaderSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    $ReaderSid = ([Security.Principal.SecurityIdentifier]::new($ReaderSid)).Value
    if (-not $admin) {
        if (-not $Elevate) { throw 'Use Install.cmd and accept the Windows administrator prompt.' }
        & (Join-Path $PSScriptRoot 'Build.ps1')
        $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-ReaderSid',$ReaderSid)
        $process = Start-Process -FilePath $powershell -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw 'Installation failed or was cancelled. See install-error.txt in the extracted folder.' }
    } else {
        . (Join-Path $PSScriptRoot 'Discovery.ps1')
        $null = Get-Plan $ReaderSid
        $marker = Join-Path $destination 'package-version.txt'
        if (Test-Path -LiteralPath $destination) {
            # An unversioned personal install must not be overwritten by a public preview.
            if (-not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $version) {
                throw 'An existing installation of another or unknown version was found and was not changed. See README.txt before upgrading.'
            }
            $saved = Get-Content -LiteralPath (Join-Path $destination 'engine-config.json') -Raw | ConvertFrom-Json
            if ($saved.ReaderSid -ne $ReaderSid) { throw 'VPN Guard is already configured for another Windows user.' }
        } else {
            foreach ($name in @('VpnGuardEngine','VpnGuardMonitor')) {
                if (Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue) { throw ('Existing task found: ' + $name) }
            }
            & (Join-Path $PSScriptRoot 'Build.ps1')
            New-Item -ItemType Directory -Path $destination | Out-Null
            & icacls.exe $destination '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not secure the install directory.' }
            foreach ($name in @('WfpGuard.Session.dll','WfpGuard.cs','Control.ps1','Discovery.ps1','Engine.ps1','Session.ps1','Watch.ps1','Panel.ps1','MonitorSetup.ps1','VpnGuard.ico','README.txt','LICENSE.txt')) {
                Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $destination $name)
            }
            [ordered]@{ReaderSid=$ReaderSid} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'engine-config.json') -Encoding UTF8
            $version | Set-Content -LiteralPath $marker -Encoding UTF8
        }
        $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f (Join-Path $destination 'Engine.ps1')) -WorkingDirectory $destination
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName 'VpnGuardEngine' -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Manage selected-app WFP filters during Amnezia VPN sessions.' -Force | Out-Null
        Start-ScheduledTask -TaskName 'VpnGuardEngine' -TaskPath '\'
        . (Join-Path $destination 'Session.ps1')
        Add-Type -Path (Join-Path $destination 'WfpGuard.Session.dll')
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        $ready = $false
        do {
            try { $null = Get-GuardStatus $destination; $ready = $true }
            catch { Start-Sleep -Milliseconds 500 }
        } until ($ready -or [DateTime]::UtcNow -gt $deadline)
        if (-not $ready) { throw 'Engine did not report a verified current status. Inspect engine-health.json; use Remove.cmd to disable a partial install.' }
        . (Join-Path $destination 'MonitorSetup.ps1')
        Register-GuardMonitor $ReaderSid
    }
    if ($ReaderSid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut((Join-Path $shell.SpecialFolders.Item('Desktop') 'VPN Guard.lnk'))
        $shortcut.TargetPath = $powershell
        $shortcut.Arguments = '-STA -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $destination 'Panel.ps1') + '"'
        $shortcut.WorkingDirectory = $destination
        $shortcut.IconLocation = (Join-Path $destination 'VpnGuard.ico') + ',0'
        $shortcut.WindowStyle = 7
        $shortcut.Save()
    }
    Write-Host 'VPN Guard installed. Open the desktop shortcut or Status.cmd. Without Amnezia it waits without blocking selected apps.'
    exit 0
} catch {
    $_.Exception.Message | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'install-error.txt') -Encoding UTF8
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
