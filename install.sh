#!/bin/sh
# Specie — cross-platform installer (macOS / Linux / any POSIX shell).
# Idempotent: safe to re-run. Creates a local virtualenv and installs the
# package in editable mode, then verifies the CLI. Pure-stdlib project — no
# third-party runtime dependencies are downloaded.
set -e

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

VENV="$ROOT/.venv"

# Pick an interpreter: prefer python3, fall back to python.
if command -v python3 >/dev/null 2>&1; then
    PYBOOT=python3
elif command -v python >/dev/null 2>&1; then
    PYBOOT=python
else
    echo "ERROR: no python3/python on PATH. Install Python 3.9+ first." >&2
    exit 1
fi

echo ">>> Using bootstrap interpreter: $($PYBOOT --version 2>&1) ($PYBOOT)"

if [ ! -d "$VENV" ]; then
    echo ">>> Creating virtualenv at .venv"
    "$PYBOOT" -m venv "$VENV"
else
    echo ">>> Reusing existing virtualenv at .venv"
fi

PY="$VENV/bin/python"

echo ">>> Upgrading pip"
"$PY" -m pip install --upgrade pip >/dev/null

echo ">>> Installing specie (editable)"
"$PY" -m pip install -e .

# Install a dev/test extra only if pyproject actually declares one.
EXTRA=$("$PY" - <<'PYEOF'
try:
    import tomllib
    with open("pyproject.toml", "rb") as f:
        extras = (tomllib.load(f).get("project") or {}).get("optional-dependencies") or {}
    print("dev" if "dev" in extras else ("test" if "test" in extras else ""))
except Exception:
    print("")
PYEOF
)
if [ -n "$EXTRA" ]; then
    echo ">>> Installing '$EXTRA' extra"
    "$PY" -m pip install -e ".[$EXTRA]"
fi

# Also honor a requirements file if present.
for req in requirements.txt requirements-dev.txt; do
    if [ -f "$ROOT/$req" ]; then
        echo ">>> Installing from $req"
        "$PY" -m pip install -r "$ROOT/$req"
    fi
done

echo ">>> Verifying CLI"
"$VENV/bin/specie" --help >/dev/null && echo "    specie --help OK"

cat <<EOF

============================================================
 Specie installed.
============================================================
 Activate the virtualenv, then run the CLI:

   bash / zsh:    source .venv/bin/activate
   fish:          source .venv/bin/activate.fish

   specie --help
   specie demo --stix bundle.stix.json --json product.json
   python examples/run_all_demos.py

 Or run without activating:

   .venv/bin/specie --help
============================================================
EOF
