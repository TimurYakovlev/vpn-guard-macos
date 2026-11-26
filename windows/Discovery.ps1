function Get-GuardTunnels {
    [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
        $_.Name -eq 'tun2' -and $_.Description -match '^tun2socks Tunnel(?: #\d+)?$' -and $_.OperationalStatus -eq 'Up'
    } | ForEach-Object Id
}

function Get-Plan([string]$ownerSid, [string[]]$tunnelGuids = @(Get-GuardTunnels)) {
    if (-not $ownerSid) { $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    $profileKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $ownerSid
    $ownerHome = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -LiteralPath $profileKey -ErrorAction Stop).ProfileImagePath)
    if (-not (Test-Path -LiteralPath $ownerHome -PathType Container)) { throw 'Windows user profile not found.' }
    $packages = @(Get-AppxPackage -User $ownerSid -ErrorAction Stop | Where-Object {
        $_.Name -in @('OpenAI.Codex','OpenAI.ChatGPT','Claude')
    })
    $targets = [Collections.Generic.List[string]]::new()
    $apps = [Collections.Generic.List[string]]::new()
    foreach ($package in $packages) {
        $found = $false
        foreach ($name in @('ChatGPT.exe','Claude.exe','Codex.exe','resources\codex.exe','resources\claude.exe')) {
            $path = Join-Path (Join-Path $package.InstallLocation 'app') $name
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $targets.Add([IO.Path]::GetFullPath($path)); $found = $true
            }
        }
        if ($found) { $apps.Add($package.Name) }
        else { throw ('Unsupported app package layout: ' + $package.Name) }
    }
    $claudePaths = @(
        (Join-Path $ownerHome '.local\bin\claude.exe'),
        (Join-Path $ownerHome 'AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe')
    )
    foreach ($path in $claudePaths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { $targets.Add($path); $apps.Add('Claude Code') }
    }
    $codexRoots = @(
        (Join-Path $ownerHome 'AppData\Local\OpenAI\Codex\bin'),
        (Join-Path $ownerHome 'AppData\Roaming\npm\node_modules\@openai\codex\vendor'),
        (Join-Path $ownerHome 'AppData\Roaming\npm\node_modules\@openai\codex-win32-x64\vendor')
    )
    foreach ($folder in $codexRoots) {
        foreach ($file in @(Get-ChildItem -LiteralPath $folder -Filter 'codex.exe' -Recurse -File -ErrorAction SilentlyContinue)) {
            $targets.Add($file.FullName); $apps.Add('Codex CLI')
        }
    }
    if ($targets.Count -eq 0) { throw 'No supported apps found. See README.txt for supported install locations.' }
    [ordered]@{
        Schema = 1
        Apps = @($apps | Sort-Object -Unique)
        Paths = @($targets | Sort-Object -Unique)
        Packages = @($packages.PackageFamilyName | Sort-Object -Unique)
        TunnelGuids = $tunnelGuids
        TunnelName = 'tun2'
        TunnelDescription = 'tun2socks Tunnel'
        Scope = 'Native Windows processes only; local IPC allowed; shared DNS and WSL/VMs outside policy.'
        CliUpdates = 'Refresh rules before using an updated executable at a new path.'
    }
}
