# Specie - cross-platform installer (Windows / PowerShell).
# Idempotent: safe to re-run. Creates a local virtualenv and installs the
# package in editable mode, then verifies the CLI. Pure-stdlib project - no
# third-party runtime dependencies are downloaded.
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Venv = Join-Path $Root '.venv'

# Pick a bootstrap interpreter: prefer 'py -3', then python3, then python.
$PyBoot = $null
if (Get-Command py -ErrorAction SilentlyContinue) { $PyBoot = @('py', '-3') }
elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $PyBoot = @('python3') }
elseif (Get-Command python -ErrorAction SilentlyContinue) { $PyBoot = @('python') }
if (-not $PyBoot) {
    Write-Error "No python/py on PATH. Install Python 3.9+ (python.org) first."
}

Write-Host ">>> Using bootstrap interpreter: $($PyBoot -join ' ')"

if (-not (Test-Path $Venv)) {
    Write-Host ">>> Creating virtualenv at .venv"
    & $PyBoot[0] $PyBoot[1..($PyBoot.Length - 1)] -m venv $Venv
} else {
    Write-Host ">>> Reusing existing virtualenv at .venv"
}

$Py = Join-Path $Venv 'Scripts\python.exe'
$Cli = Join-Path $Venv 'Scripts\specie.exe'

Write-Host ">>> Upgrading pip"
& $Py -m pip install --upgrade pip | Out-Null

Write-Host ">>> Installing specie (editable)"
& $Py -m pip install -e .

# Install a dev/test extra only if pyproject actually declares one.
$extra = & $Py -c @"
try:
    import tomllib
    with open('pyproject.toml','rb') as f:
        e=(tomllib.load(f).get('project') or {}).get('optional-dependencies') or {}
    print('dev' if 'dev' in e else ('test' if 'test' in e else ''))
except Exception:
    print('')
"@
$extra = "$extra".Trim()
if ($extra) {
    Write-Host ">>> Installing '$extra' extra"
    & $Py -m pip install -e ".[$extra]"
}

# Also honor a requirements file if present.
foreach ($req in @('requirements.txt', 'requirements-dev.txt')) {
    $reqPath = Join-Path $Root $req
    if (Test-Path $reqPath) {
        Write-Host ">>> Installing from $req"
        & $Py -m pip install -r $reqPath
    }
}

Write-Host ">>> Verifying CLI"
& $Cli --help | Out-Null
Write-Host "    specie --help OK"

Write-Host @"

============================================================
 Specie installed.
============================================================
 Activate the virtualenv, then run the CLI:

   PowerShell:    .\.venv\Scripts\Activate.ps1
   cmd.exe:       .\.venv\Scripts\activate.bat

   specie --help
   specie demo --stix bundle.stix.json --json product.json
   python examples\run_all_demos.py

 Or run without activating:

   .\.venv\Scripts\specie.exe --help
============================================================
"@
