import json
from io import BytesIO

from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from .diff import cvss_score

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"), "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#d97706"), "LOW": colors.HexColor("#65a30d"),
    "UNKNOWN": colors.HexColor("#6b7280"),
}


def _vbar(crit, high, med, low, unk) -> Drawing:
    d = Drawing(380, 170)
    items = [
        (crit or 0, colors.HexColor("#dc2626"), "CRIT"),
        (high or 0, colors.HexColor("#ea580c"), "HIGH"),
        (med or 0, colors.HexColor("#d97706"), "MED"),
        (low or 0, colors.HexColor("#65a30d"), "LOW"),
        (unk or 0, colors.HexColor("#6b7280"), "UNK"),
    ]
    mx = max([n for n, _, _ in items] + [1])
    x = 28
    for n, col, label in items:
        h = 120 * n / mx
        d.add(Rect(x, 28, 44, max(h, 0.4), fillColor=col, strokeColor=None))
        d.add(String(x + 6, 12, label, fontSize=7, fillColor=colors.HexColor("#475569")))
        d.add(String(x + 8, 32 + h, str(n), fontSize=7, fillColor=colors.HexColor("#0f172a")))
        x += 68
    return d


def _pie_chart(crit, high, med, low, unk) -> Drawing:
    d = Drawing(380, 170)
    pairs = [
        (crit or 0, colors.HexColor("#dc2626"), "CRITICAL"),
        (high or 0, colors.HexColor("#ea580c"), "HIGH"),
        (med or 0, colors.HexColor("#d97706"), "MEDIUM"),
        (low or 0, colors.HexColor("#65a30d"), "LOW"),
        (unk or 0, colors.HexColor("#6b7280"), "UNKNOWN"),
    ]
    data = [n for n, _, _ in pairs if n]
    cols = [c for n, c, _ in pairs if n]
    labs = [f"{l} {n}" for n, _, l in pairs if n]
    if not data:
        d.add(String(110, 80, "Brak podatności", fontSize=11, fillColor=colors.HexColor("#16a34a")))
        return d
    pie = Pie()
    pie.x = 20
    pie.y = 20
    pie.width = 125
    pie.height = 125
    pie.data = data
    pie.labels = labs
    pie.sideLabels = 1
    pie.simpleLabels = 0
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = colors.white
    for i, c in enumerate(cols):
        pie.slices[i].fillColor = c
    d.add(pie)
    return d


def build_pdf(scan, epss_map=None) -> bytes:
    epss_map = epss_map or {}
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4),
                            leftMargin=24, rightMargin=24, topMargin=28, bottomMargin=28)
    styles = getSampleStyleSheet()
    cell = ParagraphStyle("cell", parent=styles["Normal"], fontSize=6.5, leading=8)
    story = [
        Paragraph(f"Raport Trivy — {scan.image}", styles["Title"]),
        Paragraph(
            f"Data skanu: {scan.created_at:%Y-%m-%d %H:%M} UTC"
            + (f" · autor: {scan.created_by}" if getattr(scan, "created_by", None) else ""),
            styles["Normal"]),
        Paragraph(
            f"CRITICAL: {scan.critical} | HIGH: {scan.high} | MEDIUM: {scan.medium} "
            f"| LOW: {scan.low} | UNKNOWN: {scan.unknown}", styles["Heading3"]),
        Spacer(1, 8),
    ]

    charts = Table(
        [[_vbar(scan.critical, scan.high, scan.medium, scan.low, scan.unknown),
          _pie_chart(scan.critical, scan.high, scan.medium, scan.low, scan.unknown)]],
        colWidths=[390, 390],
    )
    charts.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(charts)
    story.append(Spacer(1, 12))

    report = json.loads(scan.result_json or "{}")
    rows = [["Sev", "CVE", "CVSS", "EPSS", "KEV", "Pakiet", "Wersja", "Fix", "Tytuł"]]
    row_styles = []
    vulns = []
    for res in report.get("Results") or []:
        vulns.extend(res.get("Vulnerabilities") or [])
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    def _vk(v):
        cid = v.get("VulnerabilityID") or ""
        inf = epss_map.get(cid) or {}
        return (
            0 if inf.get("kev") else 1,
            -(inf.get("epss") or 0),
            order.get(v.get("Severity", "UNKNOWN"), 5),
            cid,
        )

    vulns.sort(key=_vk)

    for i, v in enumerate(vulns, start=1):
        sev = v.get("Severity", "UNKNOWN")
        cid = v.get("VulnerabilityID", "")
        inf = epss_map.get(cid) or {}
        ep = inf.get("epss")
        epss_txt = f"{ep * 100:.1f}%" if isinstance(ep, (int, float)) else "-"
        kev_txt = "KEV" if inf.get("kev") else ""
        rows.append([
            sev,
            cid,
            str(cvss_score(v) if cvss_score(v) is not None else "-"),
            epss_txt,
            kev_txt,
            Paragraph(v.get("PkgName", ""), cell),
            Paragraph(v.get("InstalledVersion", ""), cell),
            Paragraph(v.get("FixedVersion", "-"), cell),
            Paragraph((v.get("Title") or "")[:140], cell),
        ])
        row_styles.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLORS.get(sev, colors.black)))
        if inf.get("kev"):
            row_styles.append(("TEXTCOLOR", (4, i), (4, i), colors.HexColor("#dc2626")))

    table = Table(rows, colWidths=[48, 92, 40, 42, 32, 88, 78, 78, 292], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 6.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        *row_styles,
    ]))
    story.append(table if vulns else Paragraph("Brak wykrytych podatności 🎉", styles["Heading2"]))

    if getattr(scan, "secrets_enabled", False):
        secrets = []
        for res in report.get("Results") or []:
            for s in res.get("Secrets") or []:
                secrets.append({**s, "Target": res.get("Target", "")})

        story.append(Spacer(1, 16))
        story.append(Paragraph(
            f"Sekrety: {len(secrets)} znalezionych" if secrets else "Sekrety: brak",
            styles["Heading3"]
        ))

        if secrets:
            srows = [["Severity", "Kategoria", "Tytuł", "Plik", "Linia"]]
            srow_styles = []
            for i, s in enumerate(secrets, start=1):
                sev = s.get("Severity", "UNKNOWN")
                srows.append([
                    sev, s.get("Category", ""),
                    Paragraph((s.get("Title") or "")[:100], cell),
                    Paragraph(s.get("Target", ""), cell),
                    str(s.get("StartLine", "-")),
                ])
                srow_styles.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLORS.get(sev, colors.black)))

            stable = Table(srows, colWidths=[55, 90, 300, 260, 45], repeatRows=1)
            stable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                *srow_styles,
            ]))
            story.append(stable)
        else:
            story.append(Paragraph("Nie znaleziono sekretów 🎉", styles["Normal"]))

    doc.build(story)
    return buf.getvalue()