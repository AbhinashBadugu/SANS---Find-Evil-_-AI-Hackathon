"""Build a Universal Case Manifest from any case folder (discovery only).

    python -m eval.build_manifest --case-root /cases/<dir> --case-id <id>

Walks the folder (metadata only — no content reads, no hashing, no forensic
tools, no shell), classifies evidence across Windows/Linux/macOS, groups it by
host, and writes `case_manifest.json`.

By design it NEVER writes into the evidence folder. Output defaults to
`./case_manifest.json`; pass --output to place it under your analysis area.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.case_manifest import scan_case_folder  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Universal Case Manifest Builder (discovery only).")
    ap.add_argument("--case-root", required=True, help="folder to scan for evidence")
    ap.add_argument("--case-id", default=None, help="case id (default: case-root folder name)")
    ap.add_argument("--output", default="case_manifest.json",
                    help="where to write the manifest JSON (NEVER the evidence folder)")
    args = ap.parse_args()

    manifest = scan_case_folder(Path(args.case_root), case_id=args.case_id)

    out = Path(args.output).expanduser().resolve()
    if str(out).startswith(str(Path(args.case_root).expanduser().resolve()) + "/"):
        print("REFUSED: refusing to write the manifest inside the evidence folder "
              "(evidence is read-only). Pass --output elsewhere.", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    print(f"=== Universal Case Manifest: {manifest.case_id} ===")
    print(f"  case_root: {manifest.case_root}")
    print(f"  hosts:     {len(manifest.hosts)}   unassigned: {len(manifest.unassigned_evidence)}")
    print(f"  {'host_id':22} {'os_family':9} {'role':18} {'#ev':4} capabilities")
    for h in manifest.hosts:
        caps = [k.replace("has_", "") for k, v in h.evidence_capabilities.model_dump().items() if v]
        print(f"  {h.host_id:22} {h.os_family.value:9} {h.host_role.value:18} "
              f"{len(h.evidence_files):<4} {', '.join(caps) or '-'}")
    print(f"\n  -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
