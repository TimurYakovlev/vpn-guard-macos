function Get-NextGuardMode([string]$Mode, [bool]$TunnelUp, [string]$Command) {
    if ($Command -eq 'End') { if ($TunnelUp) { return 'Paused' }; return 'Waiting' }
    if ($Command -eq 'Begin') { if ($TunnelUp) { return 'Armed' }; return 'Waiting' }
    if ($Mode -eq 'Armed') { return 'Armed' }
    if ($Mode -eq 'Paused' -and $TunnelUp) { return 'Paused' }
    if ($TunnelUp) { return 'Armed' }
    return 'Waiting'
}

function Open-GuardEvent([string]$Command, [string]$ReaderSid) {
    $name = "Global\VpnGuardSession-$Command-$ReaderSid"
    $security = [Security.AccessControl.EventWaitHandleSecurity]::new()
    foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $security.AddAccessRule([Security.AccessControl.EventWaitHandleAccessRule]::new($identity, 'FullControl', 'Allow'))
    }
    $reader = [Security.Principal.SecurityIdentifier]::new($ReaderSid)
    $security.AddAccessRule([Security.AccessControl.EventWaitHandleAccessRule]::new($reader, 'Modify', 'Allow'))
    $created = $false
    [Threading.EventWaitHandle]::new($false, 'AutoReset', $name, [ref]$created, $security)
}

function Send-GuardCommand([ValidateSet('Begin','End')][string]$Command) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $handle = [Threading.EventWaitHandle]::OpenExisting("Global\VpnGuardSession-$Command-$sid", 'Modify')
    try { if (-not $handle.Set()) { throw 'Не удалось передать команду VPN Guard.' } }
    finally { $handle.Dispose() }
}

function Write-GuardJson([string]$Path, $Value) {
    $temp = "$Path.tmp"
    [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temp, $Path) }
}

function Get-GuardStatus([string]$Root) {
    $state = Get-Content -LiteralPath (Join-Path $Root 'state.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $healthPath = Join-Path $Root 'engine-health.json'
    $health = Get-Content -LiteralPath $healthPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($health.Error) { throw $health.Error }
    if (((Get-Date) - (Get-Item -LiteralPath $healthPath).LastWriteTime).TotalSeconds -gt 20) { throw 'Системный сторож не отвечает.' }
    if ($state.Mode -eq 'Armed') {
        if (-not [VpnGuard]::IsActive([string[]]$state.ProofKeys)) { throw 'Сетевые правила VPN Guard не подтверждены.' }
        if (@($state.TunnelGuids).Count -gt 0) { return 'Рабочая сессия · Amnezia подключена' }
        return 'Обрыв VPN · прямой выход заблокирован'
    }
    if ($state.Mode -eq 'Paused') { return 'Сессия завершена · можно отключить Amnezia' }
    if ($state.Mode -eq 'Waiting') { return 'Ожидание Amnezia · блокировок нет' }
    throw 'Состояние VPN Guard неизвестно.'
}
