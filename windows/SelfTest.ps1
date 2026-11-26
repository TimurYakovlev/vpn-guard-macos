$ErrorActionPreference = 'Stop'
$passed = 0
function Assert($condition, [string]$message) {
    if (-not $condition) { throw ('FAIL: ' + $message) }
    $script:passed++
    Write-Host ('PASS: ' + $message)
}
foreach ($file in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1') {
    $tokens = $null; $parseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
    Assert (@($parseErrors).Count -eq 0) ('PowerShell syntax: ' + $file.Name)
}
Add-Type -Path (Join-Path $PSScriptRoot 'WfpGuard.Session.dll')
[VpnGuard]::CheckLayout()
Assert $true 'Native WFP structures have the required x64 layout (no WFP session opened)'
. (Join-Path $PSScriptRoot 'Session.ps1')
$transitions = @(
    @('Waiting',$false,'','Waiting'), @('Waiting',$true,'','Armed'),
    @('Armed',$false,'','Armed'), @('Armed',$true,'','Armed'),
    @('Armed',$true,'End','Paused'), @('Armed',$false,'End','Waiting'),
    @('Paused',$true,'','Paused'), @('Paused',$false,'','Waiting'),
    @('Paused',$true,'Begin','Armed'), @('Waiting',$false,'Begin','Waiting')
)
foreach ($case in $transitions) {
    $mode = Get-NextGuardMode $case[0] $case[1] $case[2]
    Assert ($mode -eq $case[3]) ('Session transition: ' + ($case -join ' / '))
}
$event = Open-GuardEvent ('Test-' + [Guid]::NewGuid().ToString('N')) 'S-1-5-21-111-222-333-1001'
try {
    $rights = @($event.GetAccessControl().GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))
    Assert (@($rights | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-21-111-222-333-1001' -and $_.EventWaitHandleRights -eq 'Modify' }).Count -eq 1) 'Session event grants only Modify to the selected account'
    Assert (@($rights | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-18' -and $_.EventWaitHandleRights -eq 'FullControl' }).Count -eq 1) 'SYSTEM retains FullControl of the session event'
} finally { $event.Dispose() }
foreach ($name in @('policy.json','state.json','engine-config.json','engine-health.json','install-error.txt')) {
    Assert (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name))) ('No machine-specific runtime data: ' + $name)
}
$fixtureRoot = Join-Path $PSScriptRoot ('test-fixtures-' + [Guid]::NewGuid().ToString('N'))
$script:fixtureHome = Join-Path $fixtureRoot 'Friend Profile'
$appRoot = Join-Path $fixtureRoot 'Package'
try {
    $null = New-Item -ItemType Directory -Path (Join-Path $script:fixtureHome '.local\bin'),(Join-Path $appRoot 'app') -Force
    $claude = Join-Path $script:fixtureHome '.local\bin\claude.exe'
    $desktop = Join-Path $appRoot 'app\ChatGPT.exe'
    [IO.File]::WriteAllBytes($claude,[byte[]]@(0))
    [IO.File]::WriteAllBytes($desktop,[byte[]]@(0))
    & {
        . (Join-Path $PSScriptRoot 'Discovery.ps1')
        function Get-GuardTunnels { @('fixture-tunnel') }
        function Get-ItemProperty { param($LiteralPath,$ErrorAction) [pscustomobject]@{ProfileImagePath=$script:fixtureHome} }
        function Get-AppxPackage { param($User,$ErrorAction) $script:seenSid=$User; $script:fixturePackages }
        $fakeSid = 'S-1-5-21-111-222-333-1001'
        $script:fixturePackages = @()
        $plan = Get-Plan $fakeSid
        Assert (@($plan.TunnelGuids).Count -eq 1 -and $plan.TunnelGuids[0] -eq 'fixture-tunnel') 'Discovery includes only the supplied trusted tunnels'
        Assert ($script:seenSid -eq $fakeSid) 'Discovery uses the intended Windows account'
        Assert (@($plan.Paths).Count -eq 1 -and $plan.Paths[0] -eq $claude) 'A different user profile with only Claude Code is supported'
        Assert (@($plan.Packages).Count -eq 0) 'Missing desktop apps do not prevent CLI-only installation'
        $script:fixturePackages = @([pscustomobject]@{Name='OpenAI.Codex';InstallLocation=$appRoot;PackageFamilyName='OpenAI.Codex_example'})
        $plan = Get-Plan $fakeSid
        Assert ($desktop -in $plan.Paths -and $claude -in $plan.Paths) 'Desktop package and native CLI are discovered together'
        Assert ('OpenAI.Codex_example' -in $plan.Packages) 'The discovered package family is included in the policy'
        Remove-Item -LiteralPath $claude
        $plan = Get-Plan $fakeSid
        Assert (@($plan.Paths).Count -eq 1 -and $plan.Paths[0] -eq $desktop) 'Desktop-only installation does not require both CLI tools'
        $script:fixturePackages = @()
        $failed = $false
        try { $null = Get-Plan $fakeSid } catch { $failed = $_.Exception.Message -match 'No supported apps' }
        Assert $failed 'An empty target list is rejected'
        $script:fixturePackages = @([pscustomobject]@{Name='Claude';InstallLocation=(Join-Path $fixtureRoot 'Missing');PackageFamilyName='Claude_example'})
        $failed = $false
        try { $null = Get-Plan $fakeSid } catch { $failed = $_.Exception.Message -match 'Unsupported app package layout' }
        Assert $failed 'An unknown desktop package layout is rejected'
    }
    $statusRoot = Join-Path $fixtureRoot 'Status'
    $null = New-Item -ItemType Directory -Path $statusRoot
    Write-GuardJson (Join-Path $statusRoot 'state.json') @{Mode='Waiting';FilterCount=0}
    $healthFile = Join-Path $statusRoot 'engine-health.json'
    Write-GuardJson $healthFile @{Error=$null}
    Assert ((Get-GuardStatus $statusRoot) -match 'Ожидание') 'Fresh waiting status is readable without any WFP filters'
    Write-GuardJson (Join-Path $statusRoot 'state.json') @{Mode='Paused';FilterCount=0}
    Assert ((Get-GuardStatus $statusRoot) -match 'завершена') 'Ending a session is shown without claiming network protection'
    (Get-Item -LiteralPath $healthFile).LastWriteTime = [DateTime]::Now.AddSeconds(-25)
    $failed=$false
    try { $null = Get-GuardStatus $statusRoot } catch { $failed=$true }
    Assert $failed 'A stale engine heartbeat is rejected'
} finally {
    # Delete only the freshly created fixture directory inside this package.
    $resolvedRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
    if (-not $resolvedFixture.StartsWith($resolvedRoot,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedFixture) -notmatch '^test-fixtures-[a-f0-9]{32}$') { throw 'Unsafe fixture cleanup path.' }
    if (Test-Path -LiteralPath $resolvedFixture) { Remove-Item -LiteralPath $resolvedFixture -Recurse -Force }
}
Write-Host ("Completed: $passed checks. No installer, scheduled task or network filter was run.")
