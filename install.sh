#!/usr/bin/env bash
#
# install.sh — set up the Find Evil autonomous DFIR agent for terminal use.
#
# Creates a Python virtualenv, installs dependencies, prepares config, checks for
# the system forensic tools, and runs the test suite as a smoke test.
#
# Tested on Ubuntu / SANS SIFT, Python 3.10+.
#
#   ./install.sh
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"
VENV="$REPO_DIR/.venv"
PY="${PYTHON:-python3}"

echo "=========================================================="
echo " Find Evil — Autonomous DFIR Agent : installer"
echo " repo: $REPO_DIR"
echo "=========================================================="

# 1) Python version (need 3.10+)
"$PY" - <<'PYV'
import sys
v = sys.version_info
assert v >= (3, 10), f"Python 3.10+ required, found {v.major}.{v.minor}.{v.micro}"
print(f"[ok]  python {v.major}.{v.minor}.{v.micro}")
PYV

# 2) Virtualenv
if [ ! -d "$VENV" ]; then
  echo "==> creating virtualenv at .venv"
  "$PY" -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# 3) Python dependencies
echo "==> installing Python dependencies (requirements.txt)"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r "$REPO_DIR/requirements.txt"
echo "[ok]  dependencies installed"

# 4) API-key config (chat/agent needs ANTHROPIC_API_KEY; dashboard/tests do not)
if [ ! -f "$REPO_DIR/webui/.env" ]; then
  cp "$REPO_DIR/webui/.env.example" "$REPO_DIR/webui/.env"
  echo "==> created webui/.env  —>  EDIT IT and set ANTHROPIC_API_KEY before running the agent."
else
  echo "[ok]  webui/.env already present"
fi

# 5) System forensic tools (read-only check; the agent shells out to these)
echo "==> checking system forensic tools"
miss=0
for t in vol log2timeline.py psort.py bulk_extractor fls icat ewfmount yara dotnet; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "    [ok]   $t"
  else
    echo "    [MISS] $t  (present on SANS SIFT; install via apt / vendor if missing)"
    miss=$((miss + 1))
  fi
done
[ "$miss" -gt 0 ] && echo "    note: $miss tool(s) missing — analysis steps needing them will be skipped/flagged, not faked."

# 6) Smoke test (unit tests; do not need evidence or the forensic tools)
echo "==> running test suite"
if ( cd "$REPO_DIR/agent" && PYTHONPATH="$REPO_DIR/mcp_server:$PWD" python -m pytest -q ) \
   && ( cd "$REPO_DIR/mcp_server" && PYTHONPATH="$PWD" python -m pytest -q ); then
  echo "[ok]  all tests passed"
else
  echo "[WARN] some tests failed — see output above (install still usable)"
fi

cat <<EOF

==========================================================
 Install complete. To run:
==========================================================

  # activate the venv first
  source .venv/bin/activate

  # (1) Web UI  — recommended; then open http://127.0.0.1:8077
  PYTHONPATH="$REPO_DIR" python -m webui.server

  # (2) CLI on raw evidence (strictly read-only):
  cd agent
  PYTHONPATH="$REPO_DIR/mcp_server:\$PWD" python -m eval.run_from_evidence \\
      --case mycase \\
      --evidence-root /path/to/evidence_root \\
      --host HOSTNAME disk=/path/to/HOSTNAME.E01 memory=/path/to/HOSTNAME.mem

  # (3) Re-run the tests anytime:
  cd agent && PYTHONPATH="$REPO_DIR/mcp_server:\$PWD" python -m pytest -q

Set ANTHROPIC_API_KEY in webui/.env (or 'export ANTHROPIC_API_KEY=...') first.
EOF
