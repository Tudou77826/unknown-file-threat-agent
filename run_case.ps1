$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$PythonBin = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $PythonBin)) {
    throw "Project virtual environment not found at $PythonBin. Run 'uv sync --extra dev' in $ProjectRoot."
}

Push-Location $ProjectRoot
try {
    & $PythonBin -m threat_agent.bootstrap.cli @args
}
finally {
    Pop-Location
}
