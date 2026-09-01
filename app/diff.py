import json

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def iter_vulns(result_json):
    try:
        report = json.loads(result_json or "{}")
    except json.JSONDecodeError:
        report = {}
    for res in report.get("Results") or []:
        target = res.get("Target") or ""
        for v in res.get("Vulnerabilities") or []:
            yield v, target


def collect_cve_ids(result_json) -> list[str]:
    ids = []
    seen = set()
    for v, _ in iter_vulns(result_json):
        cid = v.get("VulnerabilityID") or ""
        if cid and cid not in seen:
            seen.add(cid)
            ids.append(cid)
    return ids


def cvss_score(v: dict):
    cvss = v.get("CVSS") or {}
    for src in ("nvd", "redhat", "ghsa", "bitnami"):
        entry = cvss.get(src)
        if entry and entry.get("V3Score") is not None:
            return entry["V3Score"]
    for entry in cvss.values():
        if not isinstance(entry, dict):
            continue
        if entry.get("V3Score") is not None:
            return entry["V3Score"]
        if entry.get("V2Score") is not None:
            return entry["V2Score"]
    return None


def flatten_vuln(v: dict, target: str = "") -> dict:
    return {
        "id": v.get("VulnerabilityID") or "",
        "severity": v.get("Severity") or "UNKNOWN",
        "pkg": v.get("PkgName") or "",
        "installed": v.get("InstalledVersion") or "",
        "fixed_version": v.get("FixedVersion") or "",
        "title": (v.get("Title") or "")[:200],
        "cvss": cvss_score(v),
        "cwe": ",".join(v.get("CweIDs") or []),
        "target": target,
    }


def _index(result_json) -> dict:
    out = {}
    for v, target in iter_vulns(result_json):
        cid = v.get("VulnerabilityID") or ""
        pkg = v.get("PkgName") or ""
        if not cid:
            continue
        out[(cid, pkg)] = flatten_vuln(v, target)
    return out


def _sev_counts(items: list[dict]) -> dict:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for it in items:
        k = (it.get("severity") or "UNKNOWN").lower()
        if k in out:
            out[k] += 1
    return out


def attach_epss(items: list[dict], epss_map: dict | None):
    epss_map = epss_map or {}
    for it in items:
        inf = epss_map.get(it.get("id") or "") or {}
        it["epss"] = inf.get("epss")
        it["percentile"] = inf.get("percentile")
        it["kev"] = bool(inf.get("kev"))
        it["ransomware"] = inf.get("ransomware")
        it["kev_name"] = inf.get("kev_name")


def sort_vuln_items(items: list[dict]):
    items.sort(key=lambda x: (
        0 if x.get("kev") else 1,
        -(x.get("epss") or 0),
        SEV_RANK.get(x.get("severity"), 9),
        x.get("id") or "",
    ))


def diff_scans(older, newer, epss_map=None) -> dict:
    a = _index(older.result_json)
    b = _index(newer.result_json)
    new_items = [b[k] for k in b if k not in a]
    fixed_items = [a[k] for k in a if k not in b]
    unchanged_items = [b[k] for k in b if k in a]
    attach_epss(new_items, epss_map)
    attach_epss(fixed_items, epss_map)
    attach_epss(unchanged_items, epss_map)
    sort_vuln_items(new_items)
    sort_vuln_items(fixed_items)
    sort_vuln_items(unchanged_items)
    return {
        "from": older.summary(),
        "to": newer.summary(),
        "summary": {
            "new": len(new_items),
            "fixed": len(fixed_items),
            "unchanged": len(unchanged_items),
            "new_severities": _sev_counts(new_items),
            "fixed_severities": _sev_counts(fixed_items),
        },
        "new": new_items,
        "fixed": fixed_items,
        "unchanged": unchanged_items,
    }