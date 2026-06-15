"""hash_evidence — fingerprint an evidence file with sha256sum so we can prove
it never changed. Reads from EVIDENCE_ROOT, writes the fingerprint into CASE_ROOT.

Also: hash_file (multi-algorithm, reads evidence OR already-extracted/mounted case
files) and compare_hashes_across_hosts (group identical binaries across hosts) —
the universal hashing layer used to correlate the same implant on multiple hosts."""

import hashlib
import json
from collections import defaultdict

from forensic_mcp.executor import run_logged_command
from forensic_mcp.paths import case_dir, ensure_host_dirs, ensure_inside_evidence, ensure_readable
from forensic_mcp.provenance import log_action, next_provenance_id, log_rejection
from forensic_mcp.schemas import (
    CompareHashesRequest,
    CompareHashesResponse,
    HashEvidenceRequest,
    HashEvidenceResponse,
    HashFileRequest,
    HashFileResponse,
    HashGroup,
    ToolStatus,
)

_ALGOS = ("md5", "sha1", "sha256")


def hash_evidence(req: HashEvidenceRequest) -> HashEvidenceResponse:
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)

    # Refuse anything that is not inside the read-only evidence area.
    try:
        evidence_path = ensure_inside_evidence(req.evidence_path)
    except Exception as e:  # noqa: BLE001
        log_rejection(
            provenance_id=provenance_id,
            case_id=req.case_id,
            host_id=req.host_id,
            tool_name="sha256sum",
            wrapper_name="hash_evidence",
            attempted=["sha256sum", str(req.evidence_path)],
            error=str(e),
        )
        return HashEvidenceResponse(
            status=ToolStatus.failed,
            case_id=req.case_id,
            host_id=req.host_id,
            evidence_path=req.evidence_path,
            provenance_id=provenance_id,
            error=str(e),
        )

    if not evidence_path.exists():
        log_rejection(
            provenance_id=provenance_id,
            case_id=req.case_id,
            host_id=req.host_id,
            tool_name="sha256sum",
            wrapper_name="hash_evidence",
            attempted=["sha256sum", str(evidence_path)],
            input_paths=[evidence_path],
            error="Evidence path does not exist",
        )
        return HashEvidenceResponse(
            status=ToolStatus.failed,
            case_id=req.case_id,
            host_id=req.host_id,
            evidence_path=evidence_path,
            provenance_id=provenance_id,
            error="Evidence path does not exist",
        )

    output_path = dirs["hashes"] / f"{evidence_path.name}.sha256.txt"
    result = run_logged_command(
        provenance_id=provenance_id,
        case_id=req.case_id,
        host_id=req.host_id,
        tool_name="sha256sum",
        wrapper_name="hash_evidence",
        command=["sha256sum", str(evidence_path)],
        input_paths=[evidence_path],
        output_paths=[output_path],
        timeout_seconds=3600,
    )

    sha256_value = None
    if result.status == "success":
        # sha256sum prints "<hash>  <path>"
        line = result.stdout_path.read_text(encoding="utf-8", errors="replace").strip()
        sha256_value = line.split()[0] if line else None
        if sha256_value:
            output_path.write_text(f"{sha256_value}  {evidence_path}\n", encoding="utf-8")

    return HashEvidenceResponse(
        status=ToolStatus.success if (result.status == "success" and sha256_value) else ToolStatus.failed,
        case_id=req.case_id,
        host_id=req.host_id,
        evidence_path=evidence_path,
        sha256=sha256_value,
        hash_output_path=output_path if sha256_value else None,
        provenance_id=provenance_id,
        error=result.error,
    )


def hash_file(req: HashFileRequest) -> HashFileResponse:
    """Hash one file with multiple algorithms (md5/sha1/sha256), in-process via
    hashlib. Reads a sealed original (EVIDENCE_ROOT) OR a file the agent already
    extracted/mounted (CASE_ROOT) — never modifies it. Appends a record to the
    host's hash manifest so compare_hashes_across_hosts can correlate later."""
    dirs = ensure_host_dirs(req.case_id, req.host_id)
    provenance_id = next_provenance_id(req.case_id)
    algos = [a.lower() for a in (req.algorithms or _ALGOS) if a.lower() in _ALGOS] or ["sha256"]

    try:
        path = ensure_readable(req.file_path)
    except Exception as e:  # noqa: BLE001
        log_rejection(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
                      tool_name="hashlib", wrapper_name="hash_file",
                      attempted=["hash", str(req.file_path)], error=str(e))
        return HashFileResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                file_path=req.file_path, provenance_id=provenance_id, error=str(e))

    if not path.exists() or not path.is_file():
        msg = "path does not exist or is not a regular file"
        log_rejection(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
                      tool_name="hashlib", wrapper_name="hash_file",
                      attempted=["hash", str(path)], input_paths=[path], error=msg)
        return HashFileResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                file_path=path, provenance_id=provenance_id, error=msg)

    hashers = {a: hashlib.new(a) for a in algos}
    size = 0
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                size += len(chunk)
                for h in hashers.values():
                    h.update(chunk)
    except OSError as e:
        log_rejection(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
                      tool_name="hashlib", wrapper_name="hash_file",
                      attempted=["hash", str(path)], input_paths=[path], error=str(e))
        return HashFileResponse(status=ToolStatus.failed, case_id=req.case_id, host_id=req.host_id,
                                file_path=path, provenance_id=provenance_id, error=str(e))

    hashes = {a: hashers[a].hexdigest() for a in algos}
    manifest = dirs["hashes"] / "hash_manifest.jsonl"
    record = {"provenance_id": provenance_id, "host_id": req.host_id,
              "path": str(path), "size": size, "hashes": hashes}
    with manifest.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    log_action(provenance_id=provenance_id, case_id=req.case_id, host_id=req.host_id,
               tool_name="hashlib", wrapper_name="hash_file",
               command=["hashlib", "+".join(algos), str(path)],
               input_paths=[path], output_paths=[manifest],
               status="success", input_sha256=hashes.get("sha256"))

    return HashFileResponse(status=ToolStatus.success, case_id=req.case_id, host_id=req.host_id,
                            file_path=path, size=size, hashes=hashes, algorithms=algos,
                            provenance_id=provenance_id)


def compare_hashes_across_hosts(req: CompareHashesRequest) -> CompareHashesResponse:
    """Group every hashed file in the case by sha256 and return the groups present
    on >=2 distinct hosts — i.e. the same binary deployed across the network. Pure
    correlation over hash manifests the agent already wrote; reads no evidence."""
    provenance_id = next_provenance_id(req.case_id)
    cdir = case_dir(req.case_id)

    groups: dict[str, dict] = defaultdict(lambda: {"hosts": set(), "paths": [], "prov": [], "size": None})
    total = 0
    for manifest in sorted(cdir.glob("hosts/*/hashes/hash_manifest.jsonl")):
        for line in manifest.open("r", encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            sha = (rec.get("hashes") or {}).get("sha256")
            if not sha:
                continue
            total += 1
            g = groups[sha]
            g["hosts"].add(rec.get("host_id"))
            g["paths"].append(rec.get("path"))
            g["prov"].append(rec.get("provenance_id"))
            g["size"] = rec.get("size")

    shared = [
        HashGroup(sha256=sha, size=g["size"], hosts=sorted(h for h in g["hosts"] if h),
                  paths=g["paths"], provenance_ids=[p for p in g["prov"] if p])
        for sha, g in groups.items() if len({h for h in g["hosts"] if h}) >= 2
    ]
    shared.sort(key=lambda hg: len(hg.hosts), reverse=True)

    out = cdir / "hash_correlation.json"
    out.write_text(json.dumps({"shared": [hg.model_dump() for hg in shared], "total_files": total},
                              indent=2), encoding="utf-8")
    log_action(provenance_id=provenance_id, case_id=req.case_id, host_id="cross_host",
               tool_name="hashlib", wrapper_name="compare_hashes_across_hosts",
               command=["compare_hashes", req.case_id], output_paths=[out], status="success")

    return CompareHashesResponse(status=ToolStatus.success, case_id=req.case_id,
                                 shared=shared, total_files=total, output_path=out,
                                 provenance_id=provenance_id)
