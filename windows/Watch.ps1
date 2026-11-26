$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
. (Join-Path $root 'Session.ps1')
$mutex = [Threading.Mutex]::new($false,'Local\VpnGuardMonitor-v1')
if (-not $mutex.WaitOne(0)) { $mutex.Dispose(); return }
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
Add-Type -Path (Join-Path $root 'WfpGuard.Session.dll')
$tray = [Windows.Forms.NotifyIcon]::new()
$tray.Icon = [Drawing.Icon]::new((Join-Path $root 'VpnGuard.ico'))
$tray.Visible = $true
$tray.Text = 'VPN Guard'
$menu = [Windows.Forms.ContextMenuStrip]::new()
function Show-GuardPanel {
    $panel = Join-Path $root 'Panel.ps1'
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -ArgumentList @('-STA','-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $panel)) | Out-Null
}
function Invoke-GuardMenu([string]$Command) {
    try { Send-GuardCommand $Command }
    catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'VPN Guard') | Out-Null }
}
$menu.Items.Add('Статус').add_Click({ Show-GuardPanel })
$menu.Items.Add('Начать сессию').add_Click({ Invoke-GuardMenu 'Begin' })
$menu.Items.Add('Завершить сессию').add_Click({ Invoke-GuardMenu 'End' })
$menu.Items.Add('Закрыть значок').add_Click({ [Windows.Forms.Application]::ExitThread() })
$tray.ContextMenuStrip = $menu
$tray.add_DoubleClick({ Show-GuardPanel })
$timer = [Windows.Forms.Timer]::new()
$timer.Interval = 2000
$timer.add_Tick({
    try { $status = Get-GuardStatus $root } catch { $status = 'VPN Guard требует внимания' }
    $tray.Text = $status.Substring(0, [Math]::Min($status.Length,63))
})
try { $timer.Start(); [Windows.Forms.Application]::Run() }
finally { $timer.Dispose(); $tray.Visible = $false; $tray.Dispose(); $menu.Dispose(); $mutex.ReleaseMutex(); $mutex.Dispose() }
