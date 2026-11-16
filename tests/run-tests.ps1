$ErrorActionPreference = 'Stop'

$php = Get-Command php -ErrorAction SilentlyContinue
if (-not $php) {
    Write-Error 'PHP CLI is required to run the tests.'
    exit 127
}

& $php.Source (Join-Path $PSScriptRoot 'run-tests.php')
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
