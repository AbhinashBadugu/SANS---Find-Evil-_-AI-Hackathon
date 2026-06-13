"""Show the universal evidence-coverage matrix for any case (read-only, no tools).

    python -m eval.coverage --evidence-root /cases/<dir> [--case-id <id>] [--output cov.md]

Scans the evidence with the Universal Case Manifest Builder, routes each host to its
OS/device-family analyzer, and prints what is parsed / present-but-wrapper-missing /
not-present. This is the demonstrable proof of "universal-ready, Windows-proven".
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfir_agent.case_manifest import scan_case_folder  # noqa: E402
from dfir_agent.coverage import host_coverage, render_coverage_markdown  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Universal evidence-coverage matrix (read-only).")
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--case-id", default=None)
    ap.add_argument("--output", default=None, help="optional path to write the Markdown report")
    args = ap.parse_args()

    manifest = scan_case_folder(Path(args.evidence_root), case_id=args.case_id)
    md = render_coverage_markdown(manifest)
    if args.output:
        Path(args.output).expanduser().write_text(md, encoding="utf-8")

    print(f"=== Universal coverage: {manifest.case_id}  ({len(manifest.hosts)} host/device) ===")
    print(f"{'host':24} {'family':14} {'conf':7} {'analyzer':22} {'parsed':6} {'wrap?':6} {'absent'}")
    for h in manifest.hosts:
        c = host_coverage(h)
        tag = "" if c["implemented"] else "*"
        print(f"{c['host_id']:24} {c['os_family']:14} {c['confidence']:7} {c['analyzer']+tag:22} "
              f"{len(c['parsed']):<6} {len(c['wrapper_missing']):<6} "
              f"{len(c['not_present'])}/{c['supported_total']}")
    print("  (* = analyzer architecture-ready; parsing wrappers are the documented next step)")
    if args.output:
        print(f"\n  Markdown written -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
