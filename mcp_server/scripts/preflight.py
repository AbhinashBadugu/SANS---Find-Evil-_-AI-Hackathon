"""Quick check that the environment is ready before running real evidence."""

import shutil

from forensic_mcp.config import CASE_ROOT, EVIDENCE_ROOT, VOLATILITY_BIN, VOL_SYMBOLS_DIR


def check_tool(name: str) -> None:
    path = shutil.which(name)
    print(f"[OK] {name}: {path}" if path else f"[MISSING] {name}")


def main() -> None:
    print(f"EVIDENCE_ROOT (read-only): {EVIDENCE_ROOT}  exists={EVIDENCE_ROOT.exists()}")
    print(f"CASE_ROOT (write):         {CASE_ROOT}  exists={CASE_ROOT.exists()}")
    print(f"VOL_SYMBOLS_DIR:           {VOL_SYMBOLS_DIR}  exists={VOL_SYMBOLS_DIR.exists()}")
    print()
    check_tool("sha256sum")
    check_tool(VOLATILITY_BIN)
    check_tool("ewfverify")
    check_tool("ewfmount")
    check_tool("mmls")
    check_tool("fsstat")
    check_tool("log2timeline.py")
    check_tool("psort.py")


if __name__ == "__main__":
    main()
