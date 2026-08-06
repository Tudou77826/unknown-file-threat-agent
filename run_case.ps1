$ErrorActionPreference = "Stop"

# Edit these values to run a different case or model.
$CaseName = 'provenance_package'  #"c2_benign"  #"c2_malicious"
$Mode = "deepagents"

$ProjectRoot = $PSScriptRoot
$PythonBin = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$CaseDir = Join-Path $ProjectRoot "cases\$CaseName"
$OutputDir = Join-Path $ProjectRoot "outputs\${CaseName}_agent"

if (-not (Test-Path -LiteralPath $PythonBin)) {
    throw "Project virtual environment not found at $PythonBin. Run 'uv sync --extra dev' in $ProjectRoot."
}

Push-Location $ProjectRoot
try {
    & $PythonBin -m threat_agent.cli `
    --case $CaseDir `
    --mode $Mode `
    --output $OutputDir
}
finally {
    Pop-Location
}
