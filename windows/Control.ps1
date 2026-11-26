param([ValidateSet('Begin','End','Apply','Lock','Status','Remove')][string]$Action = 'Status', [switch]$Elevate)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$installedRoot = Join-Path $env:ProgramFiles 'VpnGuard'
if ([IO.Path]::GetFullPath($root).TrimEnd('\') -ne [IO.Path]::GetFullPath($installedRoot).TrimEnd('\')) {
    $installedControl = Join-Path $installedRoot 'Control.ps1'
    if (-not (Test-Path -LiteralPath $installedControl)) { throw 'VPN Guard is not installed. Run Install.cmd first.' }
    & $installedControl -Action $Action -Elevate:$Elevate
    return
}
. (Join-Path $root 'Session.ps1')

if ($Action -in 'Begin','Apply','Lock') { Send-GuardCommand 'Begin'; return }
if ($Action -eq 'End') { Send-GuardCommand 'End'; return }
if ($Action -eq 'Status') { & (Join-Path $root 'Panel.ps1') -CheckOnly; return }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    if (-not $Elevate) { throw 'Для удаления VPN Guard нужны права администратора.' }
    $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-Action','Remove') -PassThru -Wait
    exit $process.ExitCode
}
foreach ($name in 'VpnGuardEngine','VpnGuardMonitor') {
    $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
    if ($task) { Stop-ScheduledTask -InputObject $task; Unregister-ScheduledTask -InputObject $task -Confirm:$false }
}
Add-Type -Path (Join-Path $root 'WfpGuard.Session.dll')
$guard = [VpnGuard]::new($false)
try {
    $guard.Remove()
    Write-GuardJson (Join-Path $root 'state.json') @{Installed=$false; FilterCount=0; Mode='Uninstalled'}
} finally { $guard.Dispose() }
