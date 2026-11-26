$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Windows x64 .NET Framework C# compiler not found.' }
& $compiler /nologo /target:library /platform:x64 /optimize+ ('/out:' + (Join-Path $PSScriptRoot 'WfpGuard.Session.dll')) (Join-Path $PSScriptRoot 'WfpGuard.cs')
if ($LASTEXITCODE -ne 0) { throw 'WfpGuard.Session.dll build failed.' }
Write-Host 'Built WfpGuard.Session.dll from the included source. No network rules were changed.'
