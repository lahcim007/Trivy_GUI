import csv
from io import StringIO

from .diff import cvss_score, iter_vulns


def build_csv(scan, epss_map=None) -> bytes:
    epss_map = epss_map or {}
    buf = StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\n")
    w.writerow([
        "Severity", "CVE", "CVSS", "EPSS", "Percentyl_EPSS", "KEV", "Ransomware",
        "Pakiet", "Wersja", "Naprawiono", "CWE", "Tytuł", "Cel", "Obraz", "Skan_ID",
    ])
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    rows = []
    for v, target in iter_vulns(scan.result_json):
        cid = v.get("VulnerabilityID") or ""
        inf = epss_map.get(cid) or {}
        cv = cvss_score(v)
        ep = inf.get("epss")
        pct = inf.get("percentile")
        rows.append((
            v.get("Severity") or "UNKNOWN",
            cid,
            cv if cv is not None else "",
            f"{ep:.6f}" if isinstance(ep, (int, float)) else "",
            f"{pct:.6f}" if isinstance(pct, (int, float)) else "",
            "TAK" if inf.get("kev") else "NIE",
            inf.get("ransomware") or "",
            v.get("PkgName") or "",
            v.get("InstalledVersion") or "",
            v.get("FixedVersion") or "",
            ",".join(v.get("CweIDs") or []),
            v.get("Title") or "",
            target,
            scan.image,
            scan.id,
        ))
    rows.sort(key=lambda r: (
        0 if r[5] == "TAK" else 1,
        -(float(r[3]) if r[3] else -1.0),
        order.get(r[0], 9),
        r[1],
    ))
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8-sig")