param([switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
. (Join-Path $root 'Session.ps1')
Add-Type -Path (Join-Path $root 'WfpGuard.Session.dll')
try { $status = Get-GuardStatus $root; $healthy = $true }
catch { $status = $_.Exception.Message; $healthy = $false }
if ($CheckOnly) {
    $state = Get-Content -LiteralPath (Join-Path $root 'state.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    [ordered]@{Healthy=$healthy; Mode=$state.Mode; FilterCount=$state.FilterCount; Status=$status} | ConvertTo-Json
    return
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$form = [Windows.Forms.Form]::new()
$form.Text = 'VPN Guard'
$form.StartPosition = 'CenterScreen'
$form.ClientSize = [Drawing.Size]::new(470,144)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$label = [Windows.Forms.Label]::new()
$label.Location = [Drawing.Point]::new(16,18)
$label.Size = [Drawing.Size]::new(440,34)
$label.Text = $status
$form.Controls.Add($label)
$instruction = [Windows.Forms.Label]::new()
$instruction.Location = [Drawing.Point]::new(16,55)
$instruction.AutoSize = $true
$instruction.Text = 'Перед ручным отключением Amnezia нажми «Завершить сессию».'
$form.Controls.Add($instruction)
$start = [Windows.Forms.Button]::new()
$start.Text = 'Начать сессию'
$start.Location = [Drawing.Point]::new(16,92)
$start.Size = [Drawing.Size]::new(180,32)
$form.Controls.Add($start)
$stop = [Windows.Forms.Button]::new()
$stop.Text = 'Завершить сессию'
$stop.Location = [Drawing.Point]::new(205,92)
$stop.Size = [Drawing.Size]::new(180,32)
$form.Controls.Add($stop)
$start.add_Click({ try { Send-GuardCommand 'Begin' } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'VPN Guard') | Out-Null } })
$stop.add_Click({ try { Send-GuardCommand 'End' } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'VPN Guard') | Out-Null } })
$timer = [Windows.Forms.Timer]::new()
$timer.Interval = 1000
$timer.add_Tick({ try { $label.Text = Get-GuardStatus $root } catch { $label.Text = $_.Exception.Message } })
try { $timer.Start(); $form.ShowDialog() | Out-Null }
finally { $timer.Dispose(); $form.Dispose() }
