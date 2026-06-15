"""Java drive-by detection rule (disk, family=java_cache).

Generic behaviour, NOT a filename match: a Java applet drive-by leaves a Java
Deployment Cache that holds BOTH a remote JAR (the applet) AND an executable /
payload download (the second stage). That co-occurrence in one cache is the
signal — independent of which JAR or payload it was.

Two functions:
  * detect_java_drive_by(records)            -> findings for the applet + each payload
  * correlate_download_to_payload(records, disk_files)
                                             -> upgrade to confirmed when a payload
                                                URL matches a file later created on disk
Both cite the parse_java_cache provenance (and the MFT provenance when correlating).
"""

from __future__ import annotations

from ..state import Confidence, EvidenceReference, Finding


def _as_dict(r) -> dict:
    return r if isinstance(r, dict) else r.model_dump()


def _basename(url: str) -> str:
    return url.split("?")[0].rstrip("/").split("/")[-1] or url


def detect_java_drive_by(records, *, host_id: str, provenance_id: str,
                         id_start: int = 1) -> list[Finding]:
    recs = [_as_dict(r) for r in (records or [])]
    jar_recs = [r for r in recs if r.get("jar_urls")]
    payload_recs = [r for r in recs if r.get("payload_urls")]
    if not jar_recs or not payload_recs:
        return []

    findings: list[Finding] = []
    n = id_start
    jar_names = sorted({_basename(u) for r in jar_recs for u in r["jar_urls"]})

    # One finding per executable/payload download that co-occurs with a remote JAR.
    for r in payload_recs:
        for url in r["payload_urls"]:
            name = _basename(url)
            findings.append(Finding(
                finding_id=f"J-{n:04d}", host_id=host_id,
                title=f"Java-delivered payload download: {name}",
                category="initial_access", entity_key=f"java_payload:{name}",
                paths=[url],
                description=(
                    f"The Java Deployment Cache shows a remote JAR ({', '.join(jar_names)}) "
                    f"AND an executable/payload download '{name}' from {url}"
                    + (f" (content-type {r.get('content_type')})" if r.get("content_type") else "")
                    + (f", last-modified {r.get('last_modified')}" if r.get("last_modified") else "")
                    + ". A signed/remote applet pulling an executable second stage is a "
                    "Java drive-by initial-access pattern (T1189/T1204)."
                ),
                confidence=Confidence.likely, rule="java_cache.drive_by",
                source_count=1,
                evidence=[EvidenceReference(
                    provenance_id=provenance_id, tool="parse_java_cache",
                    artifact_path=r.get("idx_path"), source_family="java_cache",
                    record_id=f"idx:{_basename(r.get('idx_path', ''))}",
                    note=f"Java cache .idx: remote JAR + payload download {url}",
                )],
                tags=["disk", "java_cache", "initial_access", "drive_by"],
                mitre_mapping=["T1189", "T1204"],
            ))
            n += 1
    return findings


def correlate_download_to_payload(records, disk_files, *, host_id: str,
                                  provenance_id: str, id_start: int = 1) -> list[Finding]:
    """Match a Java payload download to a file created on disk (by basename),
    confirming the dropped second stage. `disk_files` items: {name, path, ctime?,
    provenance_id?}."""
    recs = [_as_dict(r) for r in (records or [])]
    payloads = {}
    for r in recs:
        for u in r.get("payload_urls", []):
            payloads.setdefault(_basename(u).lower(), (r, u))

    findings: list[Finding] = []
    n = id_start
    for df in disk_files or []:
        name = (df.get("name") or "").lower()
        if name not in payloads:
            continue
        r, url = payloads[name]
        ev = [EvidenceReference(
            provenance_id=provenance_id, tool="parse_java_cache",
            artifact_path=r.get("idx_path"), source_family="java_cache",
            note=f"Java cache payload download {url}")]
        if df.get("provenance_id"):
            ev.append(EvidenceReference(
                provenance_id=df["provenance_id"], tool="parse_mft",
                artifact_path=df.get("path"), source_family="disk_mft",
                record_id=df.get("record_id"),
                note=f"on-disk file {df.get('name')} created at {df.get('ctime')}"))
        findings.append(Finding(
            finding_id=f"JC-{n:04d}", host_id=host_id,
            title=f"Java download landed on disk: {df.get('name')}",
            category="initial_access", entity_key=f"java_drop:{name}",
            paths=[p for p in [df.get("path"), url] if p],
            description=(
                f"The Java-cache payload '{df.get('name')}' downloaded from {url} matches a "
                f"file created on disk at {df.get('path')}. Download→drop correlation confirms "
                "the applet-delivered second stage."
            ),
            confidence=Confidence.confirmed if df.get("provenance_id") else Confidence.likely,
            rule="java_cache.download_to_disk",
            source_count=2 if df.get("provenance_id") else 1,
            evidence=ev,
            tags=["disk", "java_cache", "initial_access", "correlation"],
            mitre_mapping=["T1189", "T1204"],
        ))
        n += 1
    return findings
