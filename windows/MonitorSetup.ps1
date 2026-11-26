function Register-GuardMonitor([string]$readerSid) {
    $root=Join-Path $env:ProgramFiles 'VpnGuard'
    $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-STA -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f (Join-Path $root 'Watch.ps1')) -WorkingDirectory $root
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $readerSid
    $principal=New-ScheduledTaskPrincipal -UserId $readerSid -LogonType Interactive -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName 'VpnGuardMonitor' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Show the VPN Guard tray icon in the user session at Windows sign-in. This task does not control enforcement.' -Force | Out-Null
    Start-ScheduledTask -TaskName 'VpnGuardMonitor'
}
