"""Settings, loaded from the .env file.

Two roots, kept strictly apart:
  EVIDENCE_ROOT  -> we ONLY read from here (the sealed evidence).
  CASE_ROOT      -> we ONLY write here (our results + logbook).
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Read-only evidence. Default matches this box's /cases mount.
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", "/cases")).expanduser().resolve()

# Write-only results area for everything this server produces.
CASE_ROOT = Path(os.getenv("CASE_ROOT", "~/analysis/mcp-cases")).expanduser().resolve()

# The memory tool is `vol` on this machine (not `vol.py`).
VOLATILITY_BIN = os.getenv("VOLATILITY_BIN", "vol")

# `vol` needs a writable folder to cache downloaded symbols, or every plugin fails.
# We keep it inside CASE_ROOT so it stays in our write-only area.
VOL_SYMBOLS_DIR = CASE_ROOT / ".vol-symbols"

DEFAULT_TIMEOUT_SECONDS = int(os.getenv("DEFAULT_TIMEOUT_SECONDS", "1800"))

# Which Volatility allowlist is active.
#   False -> v1 slice: only windows.info
#   True  -> the full approved set (still an allowlist; unknown plugins stay refused)
VOL_ALLOWLIST_FULL = os.getenv("VOL_ALLOWLIST_FULL", "0") == "1"

# EZ Tools are .NET assemblies, run through `dotnet`. These paths are fixed by
# the wrapper code — the agent never supplies a path or extra options.
DOTNET_BIN = os.getenv("DOTNET_BIN", "dotnet")
EZ_TOOLS_ROOT = Path(os.getenv("EZ_TOOLS_ROOT", "/opt/zimmermantools"))
MFTECMD_DLL = EZ_TOOLS_ROOT / "MFTECmd.dll"
APPCOMPAT_DLL = EZ_TOOLS_ROOT / "AppCompatCacheParser.dll"
EVTXECMD_DLL = EZ_TOOLS_ROOT / "EvtxeCmd" / "EvtxECmd.dll"
RECMD_DLL = EZ_TOOLS_ROOT / "RECmd" / "RECmd.dll"
RECMD_BATCH = EZ_TOOLS_ROOT / "RECmd" / "BatchExamples" / os.getenv("RECMD_BATCH", "Kroll_Batch.reb")

# Fixed Plaso parser set (the agent cannot supply arbitrary parsers).
# winevt = legacy XP .evt; winevtx = modern .evtx; mft = $MFT; winreg = hives.
PLASO_PARSERS = os.getenv("PLASO_PARSERS", "mft,winreg,winevtx,winevt,prefetch,lnk,winjob")
