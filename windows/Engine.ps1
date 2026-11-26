$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
. (Join-Path $root 'Discovery.ps1')
. (Join-Path $root 'Session.ps1')
Add-Type -Path (Join-Path $root 'WfpGuard.Session.dll')
$config = Get-Content -LiteralPath (Join-Path $root 'engine-config.json') -Raw | ConvertFrom-Json
$sid = [Security.Principal.SecurityIdentifier]::new($config.ReaderSid).Value
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
$statePath = Join-Path $root 'state.json'
$healthPath = Join-Path $root 'engine-health.json'
$begin = Open-GuardEvent 'Begin' $sid
$end = Open-GuardEvent 'End' $sid
$mode = 'Waiting'
try { $saved = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $saved = $null }
if ($saved.Boot -eq $boot -and $saved.Mode -in 'Waiting','Armed','Paused') { $mode = $saved.Mode }
$signature = $null
$plan = $null
$refreshAt = [DateTime]::MinValue
$heartbeatAt = [DateTime]::MinValue
$command = ''
try {
    while ($true) {
        try {
            $tunnels = @(Get-GuardTunnels | Sort-Object -Unique)
            $nextMode = Get-NextGuardMode $mode ($tunnels.Count -gt 0) $command
            if ($nextMode -eq 'Armed' -and ($null -eq $plan -or [DateTime]::UtcNow -ge $refreshAt)) {
                $plan = Get-Plan $sid $tunnels
                $refreshAt = [DateTime]::UtcNow.AddSeconds(15)
            }
            $nextSignature = $nextMode
            if ($nextMode -eq 'Armed') { $nextSignature = (@($nextMode) + @($tunnels) + @($plan.Paths) + @($plan.Packages)) -join '|' }
            if ($signature -ne $nextSignature) {
                # Static WFP objects survive a watcher restart, but expire when Windows restarts.
                $guard = [VpnGuard]::new($false, $false, $sid, $false)
                try {
                    if ($nextMode -eq 'Armed') {
                        $count = $guard.Replace([string[]]$plan.Paths, [string[]]$plan.Packages, [string[]]$tunnels, $false)
                        if ($count -le 0 -or $guard.Count() -ne $count -or $guard.DisabledCount() -ne 0) { throw 'Не удалось проверить правила VPN Guard.' }
                        $plan.TunnelGuids = $tunnels
                        Write-GuardJson (Join-Path $root 'policy.json') $plan
                    } else {
                        $guard.Remove()
                        $count = 0
                        if ($guard.Count() -ne 0) { throw 'Не удалось снять правила VPN Guard.' }
                    }
                    Write-GuardJson $statePath ([ordered]@{
                        Time = [DateTimeOffset]::Now.ToString('o'); Boot = $boot; Mode = $nextMode
                        Installed = $true; FilterCount = $count; ProofKeys = @($guard.ProofKeys()); TunnelGuids = $tunnels
                    })
                    $mode = $nextMode
                    $signature = $nextSignature
                } finally { $guard.Dispose() }
            }
            $command = ''
            if ([DateTime]::UtcNow -ge $heartbeatAt) {
                Write-GuardJson $healthPath ([ordered]@{Time = [DateTimeOffset]::Now.ToString('o'); Error = $null})
                $heartbeatAt = [DateTime]::UtcNow.AddSeconds(5)
            }
        } catch {
            $heartbeatAt = [DateTime]::MinValue
            Write-GuardJson $healthPath ([ordered]@{Time = [DateTimeOffset]::Now.ToString('o'); Error = $_.Exception.Message})
        }
        $event = [Threading.WaitHandle]::WaitAny([Threading.WaitHandle[]]@($end, $begin), 1000)
        if ($event -eq 0) { $command = 'End' }
        if ($event -eq 1) { $command = 'Begin' }
    }
} finally { $begin.Dispose(); $end.Dispose() }
