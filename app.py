import os
import sys
import subprocess
import ipaddress
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import httpx
import streamlit as st


# ============================================================
# STREAMLIT CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI-Based Browser & Email Forensics",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PROJECT PATHS
# ============================================================

APP_DIR = Path(__file__).resolve().parent

BROWSER_DIR = APP_DIR / "browser"

BROWSER_ANALYSIS_FILE = (
    BROWSER_DIR / "browser_analysis.py"
)

HISTORY_FILE = (
    BROWSER_DIR / "browser_history.csv"
)

RESULT_FILE_BROWSER = (
    BROWSER_DIR / "browser_forensics_final.csv"
)

RESULT_FILE_ROOT = (
    APP_DIR / "browser_forensics_final.csv"
)

# Existing email-forensics project
EMAIL_PROJECT_DIR = (
    APP_DIR / "email_forensics_project"
)

EMAIL_MAIN = (
    EMAIL_PROJECT_DIR / "main.py"
)

EMAIL_INPUT_DIR = (
    EMAIL_PROJECT_DIR / "emails"
)

EMAIL_INPUT_FILE = (
    EMAIL_INPUT_DIR / "gmail_message.eml"
)

EMAIL_REPORT = (
    EMAIL_PROJECT_DIR
    / "reports"
    / "forensic_report.txt"
)

COMBINED_PDF = (
    APP_DIR / "combined_forensic_report.pdf"
)


# ============================================================
# SESSION STATE
# ============================================================

DEFAULT_STATE = {
    "analysis_complete": False,
    "browser_results": None,
    "analysis_start_date": None,
    "analysis_end_date": None,
    "email_completed": False,
    "email_report": "",
}

for key, value in DEFAULT_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ============================================================
# GOOGLE AUTHENTICATION
# ============================================================

try:
    logged_in = st.user.is_logged_in
except Exception:
    logged_in = False

if not logged_in:
    st.title("Forensic Engine")

    st.write(
        "Sign in with Google to access the forensic dashboard."
    )

    try:
        st.button(
            "🔵 Sign in with Google",
            on_click=st.login,
            use_container_width=True,
        )
    except Exception:
        st.error(
            "Google authentication is not configured. "
            "Check the Streamlit authentication configuration."
        )

    st.stop()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.success("✅ Google account authenticated")

    user_name = getattr(
        st.user,
        "name",
        "Google User",
    )

    user_email = getattr(
        st.user,
        "email",
        "",
    )

    st.markdown(f"### 👤 {user_name}")

    if user_email:
        st.caption(user_email)

    st.divider()

    st.button(
        "🚪 Sign out",
        on_click=st.logout,
        use_container_width=True,
    )

    st.divider()

    st.caption("AI-Based Digital Forensics Engine")
    st.caption("Browser History • Phishing Detection • Email Forensics")


# ============================================================
# HEADER
# ============================================================

st.title("Forensic engine")

st.write(
    "Analyze browser-history records, detect potentially "
    "phishing URLs, examine email evidence, and generate "
    "forensic reports."
)

st.info(
    "For a cloud-hosted application, browser history from your "
    "personal computer must be exported and uploaded. "
    "The cloud server cannot automatically read your local browser."
)


# ============================================================
# NORMALIZE BROWSER CSV COLUMNS
# ============================================================

def normalize_columns(df):
    df = df.copy()

    rename_map = {}

    for column in df.columns:
        name = str(column).strip().lower()

        if name in [
            "url",
            "website",
            "web address",
            "link",
        ]:
            rename_map[column] = "URL"

        elif name in [
            "visit time",
            "visit date",
            "timestamp",
            "date",
            "last visit time",
        ]:
            rename_map[column] = "Visit Time"

        elif name in [
            "title",
            "page title",
            "website title",
        ]:
            rename_map[column] = "Title"

        elif name in [
            "browser",
            "browser name",
        ]:
            rename_map[column] = "Browser"

    return df.rename(columns=rename_map)


# ============================================================
# NORMALIZE CLASSIFICATION LABELS
# ============================================================

def normalize_status_column(df):
    df = df.copy()

    if "Status" not in df.columns:
        possible_columns = [
            "Prediction",
            "Result",
            "Label",
            "Classification",
            "Verdict",
            "Risk",
        ]

        for column in possible_columns:
            if column in df.columns:
                df["Status"] = df[column]
                break

    if "Status" not in df.columns:
        df["Status"] = "UNKNOWN"

    df["Status"] = (
        df["Status"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    status_map = {
        "PHISH": "PHISHING",
        "MALICIOUS": "PHISHING",
        "MALWARE": "PHISHING",
        "UNSAFE": "PHISHING",
        "NOT SAFE": "PHISHING",
        "LEGITIMATE": "BENIGN",
        "SAFE": "BENIGN",
        "NORMAL": "BENIGN",
        "RISKY": "SUSPICIOUS",
        "WARNING": "SUSPICIOUS",
    }

    df["Status"] = df["Status"].replace(status_map)

    return df


# ============================================================
# LOCAL URL RISK ANALYSIS
#
# Fallback only: this is a heuristic, not an ML prediction.
# ============================================================

def local_url_analysis(history_df):
    df = normalize_columns(history_df)

    if "URL" not in df.columns:
        raise ValueError(
            "The browser CSV must contain a URL column."
        )

    results = []

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "password",
        "signin",
        "sign-in",
        "wallet",
        "bank",
        "confirm",
        "credential",
        "suspended",
        "recover",
        "payment",
    ]

    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".top",
        ".xyz",
        ".click",
        ".work",
    ]

    for _, row in df.iterrows():
        url = str(row.get("URL", "")).strip()

        if not url or url.lower() == "nan":
            continue

        normalized_url = (
            url if "://" in url else "http://" + url
        )

        parsed = urlparse(normalized_url)

        host = parsed.hostname or ""
        lower_url = url.lower()

        score = 0
        reasons = []

        if lower_url.startswith("http://"):
            score += 10
            reasons.append("Uses HTTP")

        if "@" in parsed.netloc:
            score += 25
            reasons.append("Contains @ in URL authority")

        try:
            ipaddress.ip_address(host)
            score += 30
            reasons.append("Uses an IP address as the host")
        except ValueError:
            pass

        found_words = [
            word
            for word in suspicious_words
            if word in lower_url
        ]

        if found_words:
            score += min(30, len(found_words) * 8)
            reasons.append(
                "Suspicious keywords: "
                + ", ".join(found_words[:5])
            )

        if any(
            host.endswith(tld)
            for tld in suspicious_tlds
        ):
            score += 15
            reasons.append("Potentially risky domain ending")

        if len(url) > 180:
            score += 10
            reasons.append("Unusually long URL")

        if host.count(".") >= 4:
            score += 10
            reasons.append("Many subdomains")

        score = min(score, 100)

        if score >= 50:
            status = "PHISHING"
        elif score >= 20:
            status = "SUSPICIOUS"
        else:
            status = "BENIGN"

        result = row.to_dict()
        result["Status"] = status
        result["Risk Score"] = score
        result["Analysis"] = (
            "; ".join(reasons)
            if reasons
            else "No significant URL risk indicators detected"
        )

        results.append(result)

    return pd.DataFrame(results)


# ============================================================
# FILTER BY INVESTIGATION DATE
# ============================================================

def filter_dates(df, start_date, end_date):
    df = normalize_columns(df)

    if "Visit Time" not in df.columns:
        st.warning(
            "The CSV has no Visit Time column. "
            "All uploaded records will be analyzed."
        )
        return df

    parsed_dates = pd.to_datetime(
        df["Visit Time"],
        errors="coerce",
        utc=True,
    )

    start_timestamp = pd.Timestamp(
        start_date,
        tz="UTC",
    )

    end_timestamp = pd.Timestamp(
        end_date + timedelta(days=1),
        tz="UTC",
    )

    filtered = df.loc[
        (parsed_dates >= start_timestamp)
        & (parsed_dates < end_timestamp)
    ].copy()

    if filtered.empty and not df.empty:
        st.warning(
            "No records matched the selected dates. "
            "The date format may be unsupported. "
            "All uploaded records will be analyzed instead."
        )
        return df

    return filtered


# ============================================================
# FIND RESULT CSV
# ============================================================

def find_result_file():
    possible_files = [
        RESULT_FILE_BROWSER,
        RESULT_FILE_ROOT,
    ]

    for path in possible_files:
        if path.is_file():
            return path

    return None


# ============================================================
# RUN EXISTING BROWSER ANALYSIS SCRIPT
# ============================================================

def run_browser_analysis(start_date, end_date):
    env = os.environ.copy()

    env["INVESTIGATION_START_DATE"] = str(start_date)
    env["INVESTIGATION_END_DATE"] = str(end_date)
    env["PYTHONUNBUFFERED"] = "1"

    return subprocess.run(
        [
            sys.executable,
            "-u",
            str(BROWSER_ANALYSIS_FILE),
        ],
        cwd=str(BROWSER_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        env=env,
    )


# ============================================================
# CALCULATE BROWSER STATISTICS
# ============================================================

def calculate_statistics(df):
    if df is None or df.empty:
        return 0, 0, 0, 0, "LOW"

    df = normalize_status_column(df)

    statuses = df["Status"]

    total = len(df)

    phishing = int(
        (statuses == "PHISHING").sum()
    )

    benign = int(
        (statuses == "BENIGN").sum()
    )

    suspicious = int(
        statuses.isin(
            ["SUSPICIOUS", "UNKNOWN"]
        ).sum()
    )

    if phishing >= 5:
        risk = "HIGH"
    elif phishing >= 1 or suspicious >= 5:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return (
        total,
        phishing,
        benign,
        suspicious,
        risk,
    )


# ============================================================
# CREATE BROWSER FORENSIC REPORT
# ============================================================

def create_report(
    df,
    start_date,
    end_date,
    total,
    phishing,
    benign,
    suspicious,
    risk,
):
    lines = [
        "=" * 60,
        "AI-BASED BROWSER FORENSIC REPORT",
        "=" * 60,
        "",
        f"Investigation Start : {start_date}",
        f"Investigation End   : {end_date}",
        "",
        "BROWSER FORENSIC SUMMARY",
        "-" * 60,
        f"Total URLs          : {total}",
        f"Phishing URLs       : {phishing}",
        f"Benign URLs         : {benign}",
        f"Suspicious URLs     : {suspicious}",
        f"Overall Risk        : {risk}",
        "",
        "URL ANALYSIS RESULTS",
        "-" * 60,
    ]

    for index, (_, row) in enumerate(
        df.iterrows(),
        start=1,
    ):
        lines.extend([
            f"Record     : {index}",
            f"URL        : {row.get('URL', '')}",
            f"Title      : {row.get('Title', '')}",
            f"Visit Time : {row.get('Visit Time', '')}",
            f"Status     : {row.get('Status', 'UNKNOWN')}",
            f"Risk Score : {row.get('Risk Score', '')}",
            f"Analysis   : {row.get('Analysis', '')}",
            "-" * 60,
        ])

    lines.extend([
        "",
        "End of Browser Forensic Report",
    ])

    return "\n".join(lines)


# ============================================================
# RUN EMAIL FORENSICS
# ============================================================

def run_email_forensics():
    if not EMAIL_PROJECT_DIR.is_dir():
        st.error("Email forensics folder was not found.")
        st.code(str(EMAIL_PROJECT_DIR))
        return False

    if not EMAIL_MAIN.is_file():
        st.error("Email main.py was not found.")
        st.code(str(EMAIL_MAIN))
        return False

    if not EMAIL_INPUT_FILE.is_file():
        st.error(
            "Email evidence file was not found. "
            "Upload an .eml file first."
        )
        st.code(str(EMAIL_INPUT_FILE))
        return False

    # Prevent an old report from being mistaken for a new result.
    if EMAIL_REPORT.exists():
        try:
            EMAIL_REPORT.unlink()
        except OSError as error:
            st.warning(
                f"Could not remove the previous report: {error}"
            )

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-u",
                str(EMAIL_MAIN),
            ],
            cwd=str(EMAIL_PROJECT_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )

        # Keep per-email subprocess logs hidden from the dashboard.
        # The user receives only the consolidated final PDF.
        if result.returncode != 0:
            st.error(
                "Email analysis failed. "
                f"Exit code: {result.returncode}"
            )
            return False

        if not EMAIL_REPORT.is_file():
            st.error(
                "The email script finished, but the expected "
                "forensic report was not generated."
            )
            st.code(str(EMAIL_REPORT))
            return False

        report_text = EMAIL_REPORT.read_text(
            encoding="utf-8",
            errors="replace",
        )

        if not report_text.strip():
            st.error("The generated email report is empty.")
            return False

        st.session_state.email_report = report_text
        st.session_state.email_completed = True

        return True

    except subprocess.TimeoutExpired:
        st.error("Email analysis exceeded the time limit.")
        return False

    except Exception as error:
        st.error("Could not run email forensics.")
        st.exception(error)
        return False


# ============================================================
# GENERATE COMBINED PDF
# ============================================================

def generate_professional_pdf(
    output_path,
    report_type,
    start_date,
    end_date,
    browser_df=None,
    email_report="",
):
    """Generate a consistently styled PDF for browser, email, or combined reports."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, KeepTogether
        )
        from xml.sax.saxutils import escape
    except ImportError as error:
        raise RuntimeError(
            "ReportLab is required. Add reportlab to requirements.txt."
        ) from error

    navy = colors.HexColor("#123B68")
    blue = colors.HexColor("#1676C5")
    teal = colors.HexColor("#0F8B8D")
    pale_blue = colors.HexColor("#EDF5FD")
    pale_green = colors.HexColor("#EAF8F0")
    pale_red = colors.HexColor("#FDEEEE")
    pale_amber = colors.HexColor("#FFF7E5")
    line = colors.HexColor("#C9DDF1")
    muted = colors.HexColor("#52677D")
    green = colors.HexColor("#16834A")
    red = colors.HexColor("#B93832")
    amber = colors.HexColor("#9A6500")

    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        rightMargin=13*mm, leftMargin=13*mm,
        topMargin=13*mm, bottomMargin=17*mm,
        title=f"AI-Based Browser & Email Forensics - {report_type.title()} Report",
        author="AI-Based Browser & Email Forensics Engine",
    )
    base = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "EngineTitle", parent=base["Title"], fontName="Helvetica-Bold",
        fontSize=15, leading=18, textColor=navy, alignment=TA_LEFT,
        spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=base["Normal"], fontSize=8, leading=10,
        textColor=muted, spaceAfter=0,
    )
    section_style = ParagraphStyle(
        "Section", parent=base["Heading2"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=navy, spaceBefore=8, spaceAfter=6,
    )
    normal_style = ParagraphStyle(
        "BodySmall", parent=base["BodyText"], fontSize=8, leading=11,
        textColor=navy, spaceAfter=3,
    )
    tiny_style = ParagraphStyle(
        "Tiny", parent=normal_style, fontSize=7, leading=9,
        wordWrap="CJK",
    )
    table_head = ParagraphStyle(
        "TableHead", parent=tiny_style, fontName="Helvetica-Bold",
        textColor=colors.white,
    )
    table_cell = ParagraphStyle(
        "TableCell", parent=tiny_style, textColor=navy,
    )
    story = []

    # Header: small shield mark and report title in the same row.
    logo = Table([[Paragraph("&#9670;", ParagraphStyle(
        "LogoMark", parent=title_style, fontSize=23, leading=25,
        textColor=blue, alignment=TA_CENTER))]], colWidths=[17*mm], rowHeights=[17*mm])
    logo.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), pale_blue),
        ("BOX", (0,0), (-1,-1), 0.8, line),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 1),
        ("RIGHTPADDING", (0,0), (-1,-1), 1),
        ("TOPPADDING", (0,0), (-1,-1), 1),
        ("BOTTOMPADDING", (0,0), (-1,-1), 1),
    ]))
    header_text = [
        Paragraph("AI-BASED BROWSER &amp; EMAIL<br/>FORENSIC ENGINE REPORT", title_style),
        Paragraph("DIGITAL EVIDENCE&nbsp;&nbsp; | &nbsp;&nbsp;AI ANALYSIS&nbsp;&nbsp; | &nbsp;&nbsp;TRUSTED INSIGHTS", subtitle_style),
    ]
    right_text = [
        Paragraph(f"<b>{escape(report_type.title())} Forensics Report</b>", normal_style),
        Paragraph("Investigate&nbsp; · &nbsp;Analyse&nbsp; · &nbsp;Report", subtitle_style),
    ]
    header = Table([[logo, header_text, right_text]], colWidths=[20*mm, 98*mm, 63*mm])
    header.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 3),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LINEBELOW", (0,0), (-1,-1), 1, line),
        ("LINEBEFORE", (2,0), (2,0), 1, blue),
    ]))
    story.extend([header, Spacer(1, 7*mm)])

    def section_heading(number, label):
        return Paragraph(
            f'<font color="#1676C5"><b>{number}</b></font>&nbsp;&nbsp;'
            f'<font color="#123B68"><b>{escape(label.upper())}</b></font>',
            section_style,
        )

    df = browser_df.copy() if browser_df is not None else None
    if df is not None and not df.empty:
        df = normalize_status_column(df)
        total, phishing, benign, suspicious, risk = calculate_statistics(df)
    elif report_type.lower() == "email":
        total = phishing = benign = suspicious = 0
        risk = "REVIEW"
    else:
        total = phishing = benign = suspicious = 0
        risk = "LOW"

    story.append(section_heading("1", "Investigation Overview"))
    if report_type.lower() == "email":
        overview_metrics = [("EMAIL EVIDENCE", "Retrieved / analysed below"), ("INVESTIGATION PERIOD", f"{start_date} to {end_date}")]
        metrics = [[Paragraph(f"<b>{escape(k)}</b><br/>{escape(str(v))}", normal_style) for k,v in overview_metrics]]
        overview = Table(metrics, colWidths=[90*mm, 90*mm])
        overview.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), pale_blue),
            ("BOX", (0,0), (-1,-1), 0.7, line),
            ("INNERGRID", (0,0), (-1,-1), 0.5, line),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(overview)
    else:
        metric_data = [
            ("INVESTIGATION START", str(start_date), pale_blue, navy),
            ("INVESTIGATION END", str(end_date), pale_blue, navy),
            ("TOTAL URLS", str(total), pale_blue, blue),
            ("PHISHING URLS", str(phishing), pale_red, red),
            ("BENIGN URLS", str(benign), pale_green, green),
            ("SUSPICIOUS URLS", str(suspicious), pale_amber, amber),
            ("OVERALL RISK", str(risk), pale_green if risk == "LOW" else pale_amber, green if risk == "LOW" else amber),
        ]
        cells = []
        for label, value, bg, fg in metric_data:
            cells.append(Paragraph(
                f'<font size="6" color="#52677D"><b>{escape(label)}</b></font><br/>'
                f'<font size="12" color="{fg.hexval()}"><b>{escape(value)}</b></font>', normal_style
            ))
        overview = Table([cells[2:7]], colWidths=[36*mm] * 5)
        overview.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,0), pale_blue),
            ("BACKGROUND", (1,0), (1,0), pale_red),
            ("BACKGROUND", (2,0), (2,0), pale_green),
            ("BACKGROUND", (3,0), (3,0), pale_amber),
            ("BACKGROUND", (4,0), (4,0), pale_green if risk == "LOW" else pale_amber),
            ("BOX", (0,0), (-1,-1), 0.6, line),
            ("INNERGRID", (0,0), (-1,-1), 0.5, line),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("TOPPADDING", (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ]))
        # A compact date band above the evidence metrics.
        dates = Table([[Paragraph(f"<b>Investigation Start:</b> {escape(str(start_date))}", normal_style),
                        Paragraph(f"<b>Investigation End:</b> {escape(str(end_date))}", normal_style)]],
                      colWidths=[90*mm, 90*mm])
        dates.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), pale_blue),
                                   ("BOX", (0,0), (-1,-1), 0.6, line),
                                   ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
                                   ("LEFTPADDING", (0,0), (-1,-1), 8),
                                   ("TOPPADDING", (0,0), (-1,-1), 5),
                                   ("BOTTOMPADDING", (0,0), (-1,-1), 5)]))
        story.extend([dates, Spacer(1, 2*mm), overview])

    if report_type.lower() in ("browser", "combined") and df is not None:
        story.append(Spacer(1, 4*mm))
        story.append(section_heading("2", "Evidence Records — Browser"))
        headers = ["#", "URL", "Title", "Visit Time", "Classification", "Risk", "Analysis"]
        data = [[Paragraph(h, table_head) for h in headers]]
        for i, (_, row) in enumerate(df.iterrows(), start=1):
            url = str(row.get("URL", "") or "Unavailable")
            title = str(row.get("Title", "") or "Unavailable")
            visit = str(row.get("Visit Time", "") or "Unavailable")
            status = str(row.get("Status", "UNKNOWN") or "UNKNOWN").upper()
            score = str(row.get("Risk Score", "Not provided") or "Not provided")
            analysis = str(row.get("Analysis", "Not provided") or "Not provided")
            data.append([
                Paragraph(str(i), table_cell),
                Paragraph(escape(url), tiny_style),
                Paragraph(escape(title), tiny_style),
                Paragraph(escape(visit), tiny_style),
                Paragraph(escape(status), tiny_style),
                Paragraph(escape(score), tiny_style),
                Paragraph(escape(analysis), tiny_style),
            ])
        evidence = Table(data, repeatRows=1,
                         colWidths=[7*mm, 48*mm, 25*mm, 21*mm, 22*mm, 13*mm, 34*mm])
        evidence.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), navy),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.45, line),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F7FAFE")]),
        ]))
        story.append(evidence)

    if report_type.lower() in ("email", "combined"):
        story.append(Spacer(1, 4*mm))
        story.append(section_heading("2" if report_type.lower() == "email" else "3", "Email Evidence & Analysis"))
        if email_report and email_report.strip():
            # Preserve the existing email analyzer output, but render it as readable paragraphs.
            for line_text in email_report.splitlines():
                clean = line_text.strip()
                if not clean:
                    story.append(Spacer(1, 1.5*mm))
                elif set(clean) <= set("=-_"):
                    story.append(Spacer(1, 1*mm))
                else:
                    story.append(Paragraph(escape(clean), normal_style))
        else:
            story.append(Paragraph("No email report content was supplied.", normal_style))

    story.append(Spacer(1, 4*mm))
    conclusion_number = "3" if report_type.lower() == "browser" else ("4" if report_type.lower() == "combined" else "3")
    story.append(section_heading(conclusion_number, "Findings & Conclusion"))
    findings = []
    if df is not None and not df.empty:
        findings.append(f"{total} browser URL record(s) were included in this report.")
        findings.append(f"Classification counts: {phishing} phishing, {benign} benign, and {suspicious} suspicious/unknown.")
        if "Visit Time" in df.columns and df["Visit Time"].astype(str).str.strip().isin(["", "NaT", "nan", "None"]).any():
            findings.append("Some visit timestamps are unavailable in the collected evidence.")
        if "Risk Score" in df.columns:
            findings.append("Risk scores are reported as supplied by the analysis pipeline and should be interpreted separately from the classification label.")
    if report_type.lower() == "email":
        findings.append("Review the email findings and source evidence before drawing investigative conclusions.")
    if not findings:
        findings.append("No structured browser evidence was supplied. Review the email analysis above and verify conclusions against original evidence.")
    findings.append("Automated results support investigation; they do not replace manual verification by an investigator.")
    finding_paras = [Paragraph("• " + escape(item), normal_style) for item in findings]
    conclusion = Table([[finding_paras]], colWidths=[180*mm])
    conclusion.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), pale_blue),
        ("BOX", (0,0), (-1,-1), 0.7, line),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]))
    story.append(conclusion)

    def draw_footer(canvas, document_obj):
        canvas.saveState()
        page_w, _ = A4
        canvas.setStrokeColor(line)
        canvas.setLineWidth(0.6)
        canvas.line(13*mm, 12*mm, page_w-13*mm, 12*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(muted)
        canvas.drawString(13*mm, 7*mm, "AI-Based Browser & Email Forensics Engine")
        canvas.drawCentredString(page_w/2, 7*mm, f"Generated: {date.today().isoformat()}  |  Page {document_obj.page}")
        canvas.drawRightString(page_w-13*mm, 7*mm, "For Investigative Use")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    return Path(output_path)


def generate_combined_pdf(browser_df, browser_report, email_report, start_date, end_date):
    """Backward-compatible wrapper for the combined branded PDF."""
    return generate_professional_pdf(
        COMBINED_PDF, "combined", start_date, end_date,
        browser_df=browser_df, email_report=email_report,
    )


# ============================================================
# INVESTIGATION PERIOD
# ============================================================

st.divider()
st.header("📅 Investigation Period")

today = date.today()

date_col1, date_col2 = st.columns(2)

with date_col1:
    start_date = st.date_input(
        "Start Date",
        value=today - timedelta(days=7),
        key="start_date_picker",
    )

with date_col2:
    end_date = st.date_input(
        "End Date",
        value=today,
        key="end_date_picker",
    )

if start_date > end_date:
    st.error("Start Date cannot be after End Date.")
    st.stop()


# ============================================================
# BROWSER ANALYSIS
# ============================================================

st.divider()
st.header("🔎 Browser Analysis")

st.write(
    "Upload the JSON exported by the Forensic Browser Extension, or a browser-history CSV. "
    "JSON exports containing url, title, visitTime, and transition are supported."
)

browser_upload = st.file_uploader(
    "Upload Browser History JSON or CSV",
    type=["json", "csv"],
    key="browser_history_upload",
)

if st.button(
    "🔎 Run Browser Analysis",
    type="primary",
    use_container_width=True,
):
    st.session_state.analysis_complete = False
    st.session_state.browser_results = None

    try:
        if browser_upload is None:
            st.error(
                "Upload the browser extension's JSON export or a browser-history CSV before running analysis."
            )
        else:
            if browser_upload.name.lower().endswith(".json"):
                import json

                json_data = json.load(browser_upload)
                if isinstance(json_data, dict):
                    json_data = json_data.get("records", json_data.get("history", []))
                if not isinstance(json_data, list):
                    st.error("The JSON file must contain a list of browser-history records.")
                    st.stop()

                uploaded_df = pd.DataFrame(json_data)
                uploaded_df = uploaded_df.rename(
                    columns={
                        "url": "URL",
                        "title": "Title",
                        "visitTime": "Visit Time",
                        "visit_time": "Visit Time",
                        "transition": "Transition",
                    }
                )
            else:
                uploaded_df = pd.read_csv(browser_upload)

            uploaded_df = normalize_columns(uploaded_df)

            if "URL" not in uploaded_df.columns:
                st.error(
                    "The uploaded CSV does not contain a URL column. "
                    "Please check the column headings."
                )
            elif uploaded_df.empty:
                st.error("The uploaded CSV contains no records.")
            else:
                filtered_df = filter_dates(
                    uploaded_df,
                    start_date,
                    end_date,
                )

                filtered_df = filtered_df.dropna(
                    subset=["URL"]
                ).copy()

                filtered_df["URL"] = (
                    filtered_df["URL"]
                    .astype(str)
                    .str.strip()
                )

                filtered_df = filtered_df[
                    filtered_df["URL"] != ""
                ]

                if filtered_df.empty:
                    st.error(
                        "No usable URLs were found in the uploaded data."
                    )
                else:
                    BROWSER_DIR.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    # Save data for the existing project pipeline.
                    filtered_df.to_csv(
                        HISTORY_FILE,
                        index=False,
                    )

                    st.success(
                        f"Loaded {len(filtered_df)} browser records."
                    )

                    model_results = None

                    if BROWSER_ANALYSIS_FILE.is_file():
                        # Remove old outputs so stale results are not reused.
                        for output_file in [
                            RESULT_FILE_BROWSER,
                            RESULT_FILE_ROOT,
                        ]:
                            try:
                                if output_file.is_file():
                                    output_file.unlink()
                            except OSError:
                                pass

                        with st.spinner(
                            "Running the existing browser-analysis pipeline..."
                        ):
                            try:
                                process = run_browser_analysis(
                                    start_date,
                                    end_date,
                                )

                                if process.stdout or process.stderr:
                                    with st.expander(
                                        "Browser analysis technical output",
                                        expanded=False,
                                    ):
                                        if process.stdout:
                                            st.code(process.stdout)

                                        if process.stderr:
                                            st.code(process.stderr)

                                result_path = find_result_file()

                                if result_path is not None:
                                    candidate_df = pd.read_csv(
                                        result_path
                                    )
                                    candidate_df = normalize_columns(
                                        candidate_df
                                    )

                                    if (
                                        not candidate_df.empty
                                        and "URL" in candidate_df.columns
                                    ):
                                        model_results = candidate_df

                            except subprocess.TimeoutExpired:
                                st.warning(
                                    "The browser-analysis script timed out. "
                                    "Trying the local URL-risk fallback."
                                )

                            except Exception as error:
                                st.warning(
                                    "The existing browser pipeline did not "
                                    f"produce usable results: {error}"
                                )
                    else:
                        st.warning(
                            "browser_analysis.py was not found. "
                            "Using the local URL-risk fallback."
                        )

                    if model_results is not None:
                        model_results = normalize_status_column(
                            model_results
                        )

                        st.session_state.browser_results = (
                            model_results
                        )

                        st.success(
                            "Browser pipeline produced a results CSV."
                        )

                    else:
                        st.warning(
                            "Using rule-based URL-risk analysis. "
                            "These results are not predictions from your trained ML model."
                        )

                        fallback_results = local_url_analysis(
                            filtered_df
                        )

                        if fallback_results.empty:
                            st.error(
                                "The URL-risk analysis returned no results."
                            )
                        else:
                            st.session_state.browser_results = (
                                fallback_results
                            )

                    if st.session_state.browser_results is not None:
                        st.session_state.analysis_complete = True

                        st.session_state.analysis_start_date = (
                            start_date
                        )

                        st.session_state.analysis_end_date = (
                            end_date
                        )

    except pd.errors.EmptyDataError:
        st.error("The uploaded CSV file is empty.")

    except Exception as error:
        st.error("Browser analysis failed.")
        st.exception(error)


# ============================================================
# DISPLAY BROWSER RESULTS
# ============================================================

if st.session_state.analysis_complete:
    df = st.session_state.browser_results.copy()
    df = normalize_status_column(df)

    (
        total,
        phishing,
        benign,
        suspicious,
        risk,
    ) = calculate_statistics(df)

    st.divider()
    st.header("📊 Browser Forensic Summary")

    # Keep all five summary metrics in one horizontal row.
    # On narrow screens, the row scrolls horizontally instead of stacking.
    summary_items = [
        ("🌐 Total URLs", total, "#2388c9"),
        ("🔴 Phishing", phishing, "#dc3545"),
        ("🟢 Benign", benign, "#20a464"),
        ("🟠 Suspicious", suspicious, "#ed8733"),
        ("⚠️ Risk", risk, "#8b78d6"),
    ]
    cards_html = "".join(
        '<div style="flex:1 0 145px; min-width:145px; box-sizing:border-box; '
        'padding:15px 14px; border:1px solid #303642; border-top:4px solid ' + color + '; '
        'border-radius:12px; background:#151922;">'
        '<div style="font-size:14px; color:#cbd5e1; margin-bottom:10px; white-space:nowrap;">' + str(label) + '</div>'
        '<div style="font-size:29px; line-height:1.15; font-weight:650; color:#f8fafc;">' + str(value) + '</div>'
        '</div>'
        for label, value, color in summary_items
    )
    st.markdown(
        '<div style="display:flex; flex-wrap:nowrap; gap:10px; width:100%; '
        'overflow-x:auto; padding:2px 1px 12px 1px;">' + cards_html + '</div>',
        unsafe_allow_html=True,
    )

    st.info(
        f"Investigation period: "
        f"{st.session_state.analysis_start_date} → "
        f"{st.session_state.analysis_end_date}"
    )

    if risk == "HIGH":
        st.error(
            "🔴 HIGH RISK: Multiple phishing URLs were classified."
        )
    elif risk == "MEDIUM":
        st.warning(
            "🟠 MEDIUM RISK: Potentially harmful URL indicators were found."
        )
    else:
        st.success(
            "🟢 LOW RISK: Few significant URL risk indicators were found."
        )

    st.divider()
    st.subheader("📄 Browser Forensic Report — Outline")

    st.markdown(
        f"""
        **1. Investigation Details**
        - Investigation period: {st.session_state.analysis_start_date} to {st.session_state.analysis_end_date}
        - Evidence source: Browser history JSON/CSV uploaded by the investigator

        **2. Evidence Overview**
        - Total URL records analyzed: **{total}**
        - Phishing classifications: **{phishing}**
        - Benign classifications: **{benign}**
        - Suspicious/unknown classifications: **{suspicious}**

        **3. Risk Assessment**
        - Overall risk level: **{risk}**

        **4. Report Contents**
        - Detailed URL, page title, visit time, classification, risk score, and analysis
        - Summary of findings and investigation conclusion

        **5. Important Note**
        - Detailed evidence and analysis are included in the downloadable PDF only.
        - Automated classifications are indicators for investigation, not final proof of malicious activity.
        """
    )

    try:
        browser_pdf_path = APP_DIR / "browser_forensic_report.pdf"
        generate_professional_pdf(
            browser_pdf_path, "browser",
            st.session_state.analysis_start_date,
            st.session_state.analysis_end_date,
            browser_df=df,
        )
        st.download_button(
            "⬇️ Download Detailed Browser Forensic PDF",
            data=browser_pdf_path.read_bytes(),
            file_name="browser_forensic_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    except Exception as error:
        st.error("Could not generate the browser PDF report.")
        st.exception(error)


# ============================================================
# GMAIL OAUTH HELPERS
# ============================================================

GMAIL_SCOPES = "https://www.googleapis.com/auth/gmail.readonly"


def gmail_oauth_settings():
    """Read OAuth web-client settings from Streamlit secrets."""
    try:
        settings = st.secrets.get("gmail_oauth", {})
        client_id = settings.get("client_id", "")
        client_secret = settings.get("client_secret", "")
        redirect_uri = settings.get("redirect_uri", "")
        return client_id, client_secret, redirect_uri
    except Exception:
        return "", "", ""


def _gmail_state_signature(nonce, client_secret):
    """Sign OAuth state so validation survives Streamlit session reruns."""
    import hashlib
    import hmac

    return hmac.new(
        client_secret.encode("utf-8"),
        nonce.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def gmail_authorization_url():
    """Build a Gmail OAuth URL with state that can be validated after redirect."""
    import secrets
    from urllib.parse import urlencode

    client_id, client_secret, redirect_uri = gmail_oauth_settings()
    if not client_id or not client_secret or not redirect_uri:
        return None

    nonce = secrets.token_urlsafe(24)
    signature = _gmail_state_signature(nonce, client_secret)
    oauth_state = nonce + "." + signature
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile " + GMAIL_SCOPES,
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": oauth_state,
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)


def handle_gmail_oauth_callback():
    """Exchange Google's authorization code for a short-lived access token."""
    import hmac

    code = st.query_params.get("code")
    returned_state = st.query_params.get("state")
    if not code:
        return

    client_id, client_secret, redirect_uri = gmail_oauth_settings()
    if not client_id or not client_secret or not redirect_uri:
        st.error("Gmail OAuth settings are missing. Configure client_id, client_secret, and redirect_uri in Streamlit Secrets.")
        st.query_params.clear()
        return

    try:
        if not returned_state or "." not in returned_state:
            raise ValueError("Missing OAuth state")
        nonce, supplied_signature = returned_state.rsplit(".", 1)
        expected_signature = _gmail_state_signature(nonce, client_secret)
        if not hmac.compare_digest(supplied_signature, expected_signature):
            st.error("Gmail authorization state could not be verified. Please connect Gmail again.")
            st.query_params.clear()
            return

        response = httpx.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=20.0,
        )
        response.raise_for_status()
        token_data = response.json()
        st.session_state["gmail_access_token"] = token_data["access_token"]
        st.session_state["gmail_token_expires_at"] = (
            __import__("time").time() + int(token_data.get("expires_in", 3600))
        )
        st.query_params.clear()
        st.success("Gmail connected successfully with read-only access.")
        st.rerun()
    except Exception:
        st.error("Google could not complete Gmail authorization. Check the OAuth client and redirect URI, then try again.")
        st.query_params.clear()


def gmail_api_get(path, params=None):
    """Call the Gmail API using the user's session access token."""
    token = st.session_state.get("gmail_access_token")
    expires_at = st.session_state.get("gmail_token_expires_at", 0)
    if not token or __import__("time").time() >= expires_at:
        raise RuntimeError("Your Gmail connection expired. Please connect Gmail again.")

    response = httpx.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/" + path,
        headers={"Authorization": "Bearer " + token},
        params=params,
        timeout=25.0,
    )
    response.raise_for_status()
    return response.json()


def list_gmail_messages(start_date, end_date):
    """List every Gmail message received during the selected date range."""
    query = (
        f"after:{start_date.strftime('%Y/%m/%d')} "
        f"before:{(end_date + timedelta(days=1)).strftime('%Y/%m/%d')}"
    )
    message_ids = []
    page_token = None

    # Gmail returns at most 500 message IDs per page. Follow every page.
    while True:
        params = {"q": query, "maxResults": 500}
        if page_token:
            params["pageToken"] = page_token
        listing = gmail_api_get("messages", params)
        message_ids.extend(listing.get("messages", []))
        page_token = listing.get("nextPageToken")
        if not page_token:
            break

    results = []
    for message in message_ids:
        metadata = gmail_api_get(
            "messages/" + message["id"],
            {"format": "metadata", "metadataHeaders": ["From", "To", "Subject", "Date"]},
        )
        headers = {
            item.get("name", "").lower(): item.get("value", "")
            for item in metadata.get("payload", {}).get("headers", [])
        }
        subject = headers.get("subject") or "(No subject)"
        sender = headers.get("from") or "(Unknown sender)"
        received = headers.get("date") or ""
        results.append({
            "id": message["id"],
            "label": f"{subject} — {sender} {('— ' + received) if received else ''}",
            "subject": subject,
            "sender": sender,
            "date": received,
        })
    return results


def download_gmail_message_as_eml(message_id):
    """Download the selected message in RFC 822 format for the existing analyzer."""
    import base64

    message = gmail_api_get("messages/" + message_id, {"format": "raw"})
    raw = message.get("raw")
    if not raw:
        raise RuntimeError("Google returned no raw email content for this message.")
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


handle_gmail_oauth_callback()


# ============================================================
# EMAIL FORENSICS
# ============================================================

st.divider()
st.header("📧 Email Forensics")
st.write(
    "Connect Gmail, select an investigation date range, and analyze every email "
    "received during that period. The detailed results are provided as a downloadable PDF."
)

client_id, client_secret, redirect_uri = gmail_oauth_settings()
gmail_connected = bool(
    st.session_state.get("gmail_access_token")
    and __import__("time").time() < st.session_state.get("gmail_token_expires_at", 0)
)

if not client_id or not client_secret or not redirect_uri:
    st.warning(
        "Gmail direct access is not configured yet. Configure the Gmail OAuth values in Streamlit Secrets."
    )
elif not gmail_connected:
    authorization_url = gmail_authorization_url()
    if authorization_url:
        st.link_button(
            "🔐 Connect Gmail (read-only)",
            authorization_url,
            use_container_width=True,
        )
    st.caption("Gmail access is read-only and separate from signing in to Forensic Engine.")
else:
    st.success("Gmail is connected for this session.")
    if st.button("Disconnect Gmail", use_container_width=True):
        st.session_state.pop("gmail_access_token", None)
        st.session_state.pop("gmail_token_expires_at", None)
        st.session_state["gmail_messages"] = []
        st.session_state["email_completed"] = False
        st.session_state["email_report"] = ""
        st.rerun()

    if st.button("📨 Find ALL emails in selected date range", use_container_width=True):
        try:
            with st.spinner("Searching all Gmail pages for the selected dates..."):
                st.session_state["gmail_messages"] = list_gmail_messages(start_date, end_date)
                st.session_state["gmail_messages_dates"] = (str(start_date), str(end_date))
            st.session_state["email_completed"] = False
            st.session_state["email_report"] = ""
            if not st.session_state["gmail_messages"]:
                st.info("No Gmail messages were found in the selected date range.")
        except Exception as error:
            st.error("Could not retrieve Gmail messages. The connection may have expired or the Gmail API may not be enabled.")
            st.caption(str(error))

    messages = st.session_state.get("gmail_messages", [])
    if messages:
        st.info(f"Found {len(messages)} email(s). The analysis button processes every email found for the selected date range.")
        if st.button("🔎 Analyze ALL emails and generate PDF", type="primary", use_container_width=True):
            st.session_state.email_completed = False
            st.session_state.email_report = ""
            import re
            email_summaries = []
            failed_emails = []
            EMAIL_INPUT_DIR.mkdir(parents=True, exist_ok=True)
            progress = st.progress(0, text="Preparing consolidated email analysis...")
            for index, message in enumerate(messages, start=1):
                try:
                    raw_email = download_gmail_message_as_eml(message["id"])
                    EMAIL_INPUT_FILE.write_bytes(raw_email)
                    with st.spinner(f"Analyzing email {index} of {len(messages)}..."):
                        success = run_email_forensics()
                    if success:
                        report_text = st.session_state.email_report
                        def field(pattern, default="Not reported"):
                            match = re.search(pattern, report_text, re.IGNORECASE | re.MULTILINE)
                            return match.group(1).strip() if match else default

                        email_summaries.append({
                            "number": index,
                            "subject": field(r"^Subject:\s*(.+)$", message.get("subject", "(No subject)")),
                            "from": field(r"^From:\s*(.+)$", message.get("sender", "(Unknown sender)")),
                            "date": field(r"^Date:\s*(.+)$", message.get("date", "")),
                            "risk": field(r"^Email Risk Level:\s*(.+)$", "UNKNOWN").upper(),
                            "urls": field(r"^Total URLs Found:\s*(\d+)\s*$", "0"),
                            "suspicious_urls": field(r"^Suspicious URLs:\s*(\d+)\s*$", "0"),
                            "spf": field(r"^SPF:\s*(.+)$"),
                            "dkim": field(r"^DKIM:\s*(.+)$"),
                            "dmarc": field(r"\bdmarc=([a-z]+)", "Not reported").upper(),
                        })
                    else:
                        failed_emails.append(message.get("label", message["id"]))
                except Exception:
                    failed_emails.append(message.get("label", message["id"]))
                progress.progress(index / len(messages), text=f"Processed {index} of {len(messages)} emails")

            if email_summaries:
                high_count = sum(item["risk"] == "HIGH" for item in email_summaries)
                medium_count = sum(item["risk"] == "MEDIUM" for item in email_summaries)
                low_count = sum(item["risk"] == "LOW" for item in email_summaries)
                unknown_count = len(email_summaries) - high_count - medium_count - low_count
                total_urls = sum(int(item["urls"]) for item in email_summaries if str(item["urls"]).isdigit())
                suspicious_urls = sum(int(item["suspicious_urls"]) for item in email_summaries if str(item["suspicious_urls"]).isdigit())
                consolidated = [
                    "CONSOLIDATED EMAIL FORENSICS FINAL REPORT",
                    "=" * 64,
                    f"Investigation period: {start_date} to {end_date}",
                    f"Emails found: {len(messages)}",
                    f"Emails successfully analyzed: {len(email_summaries)}",
                    f"Emails failed: {len(failed_emails)}",
                    "",
                    "OVERALL SUMMARY",
                    "-" * 64,
                    f"Email risk counts: HIGH={high_count}, MEDIUM={medium_count}, LOW={low_count}, UNKNOWN={unknown_count}",
                    f"Total URLs found across emails: {total_urls}",
                    f"Suspicious URLs across emails: {suspicious_urls}",
                    "",
                    "EMAIL FINDINGS (SUMMARY ONLY)",
                    "-" * 64,
                ]
                for item in email_summaries:
                    consolidated.extend([
                        f"Email {item['number']}: {item['subject']}",
                        f"From: {item['from']}",
                        f"Date: {item['date']}",
                        f"Risk: {item['risk']} | URLs: {item['urls']} | Suspicious URLs: {item['suspicious_urls']}",
                        f"Authentication: SPF={item['spf']} | DKIM={item['dkim']} | DMARC={item['dmarc']}",
                        "-" * 64,
                    ])
                if failed_emails:
                    consolidated.extend(["", "EMAILS THAT FAILED ANALYSIS", "-" * 64])
                    consolidated.extend(failed_emails)
                consolidated.extend([
                    "",
                    "CONCLUSION",
                    "-" * 64,
                    "This report consolidates findings from all successfully analyzed emails in the selected date range.",
                    "Automated risk classifications are investigative indicators and should not be treated as conclusive proof.",
                ])
                st.session_state.email_report = "\n".join(consolidated)
            else:
                st.session_state.email_report = ""
            st.session_state.email_processed_count = len(email_summaries)
            st.session_state.email_failed_count = len(failed_emails)
            st.session_state.email_completed = bool(email_summaries)
            st.session_state.email_report_start_date = start_date
            st.session_state.email_report_end_date = end_date
            st.session_state.email_failed_labels = failed_emails
            if email_summaries:
                st.success(f"Created one consolidated report from {len(email_summaries)} analyzed emails.")
            else:
                st.error("No email reports were generated. Check the email pipeline output.")
            if failed_emails:
                st.warning(f"{len(failed_emails)} email(s) could not be analyzed; their names are listed in the consolidated PDF.")

if st.session_state.get("email_completed"):
    try:
        email_pdf_path = APP_DIR / "email_forensic_report.pdf"
        failed = st.session_state.get("email_failed_labels", [])
        final_report = st.session_state.email_report
        if failed:
            final_report += "\n\nFAILED EMAILS (could not be analyzed)\n" + "\n".join(failed)
        generate_professional_pdf(
            email_pdf_path,
            "email",
            st.session_state.get("email_report_start_date", start_date),
            st.session_state.get("email_report_end_date", end_date),
            email_report=final_report,
        )
        st.download_button(
            f"⬇️ Download PDF — {st.session_state.get('email_processed_count', 0)} emails analyzed",
            data=email_pdf_path.read_bytes(),
            file_name="email_forensic_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    except Exception as error:
        st.error("Could not generate the email PDF report.")
        st.caption(str(error))


# ============================================================
# COMBINED BROWSER + EMAIL PDF
# ============================================================

st.divider()
st.header("📑 Combined Forensic Report")

if (
    st.session_state.analysis_complete
    and st.session_state.email_completed
):
    if st.button(
        "📑 Generate Combined PDF Report",
        type="primary",
        use_container_width=True,
    ):
        try:
            browser_df = st.session_state.browser_results.copy()

            (
                pdf_total,
                pdf_phishing,
                pdf_benign,
                pdf_suspicious,
                pdf_risk,
            ) = calculate_statistics(browser_df)

            browser_report_for_pdf = create_report(
                browser_df,
                st.session_state.analysis_start_date,
                st.session_state.analysis_end_date,
                pdf_total,
                pdf_phishing,
                pdf_benign,
                pdf_suspicious,
                pdf_risk,
            )

            with st.spinner("Generating combined PDF..."):
                pdf_path = generate_combined_pdf(
                    browser_df,
                    browser_report_for_pdf,
                    st.session_state.email_report,
                    st.session_state.analysis_start_date,
                    st.session_state.analysis_end_date,
                )

            pdf_bytes = pdf_path.read_bytes()

            st.success(
                "✅ Combined Browser + Email PDF generated successfully."
            )

            st.download_button(
                "⬇️ Download Combined Forensic PDF",
                data=pdf_bytes,
                file_name="combined_forensic_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        except Exception as error:
            st.error("Could not generate the combined PDF report.")
            st.exception(error)