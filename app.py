import os
import sys
import subprocess
from datetime import date, timedelta

import pandas as pd
import streamlit as st

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Preformatted,
)
from xml.sax.saxutils import escape


# ============================================================
# STREAMLIT CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Browser Forensics",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PROJECT PATHS
# ============================================================

APP_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

BROWSER_DIR = os.path.join(
    APP_DIR,
    "browser"
)

BROWSER_ANALYSIS_FILE = os.path.join(
    BROWSER_DIR,
    "browser_analysis.py"
)

HISTORY_FILE = os.path.join(
    BROWSER_DIR,
    "browser_history.csv"
)

RESULT_FILE_BROWSER = os.path.join(
    BROWSER_DIR,
    "browser_forensics_final.csv"
)

RESULT_FILE_ROOT = os.path.join(
    APP_DIR,
    "browser_forensics_final.csv"
)

# ============================================================
# EMAIL FORENSICS PATHS
# ============================================================

EMAIL_PROJECT_DIR = os.path.join(
    APP_DIR,
    "email_forensics_project"
)

EMAIL_MAIN = os.path.join(
    EMAIL_PROJECT_DIR,
    "main.py"
)

EMAIL_REPORT = os.path.join(
    EMAIL_PROJECT_DIR,
    "reports",
    "forensic_report.txt"
)

COMBINED_PDF = os.path.join(
    APP_DIR,
    "combined_forensic_report.pdf"
)


# ============================================================
# SESSION STATE
# ============================================================

if "analysis_complete" not in st.session_state:
    st.session_state.analysis_complete = False

if "browser_results" not in st.session_state:
    st.session_state.browser_results = None

if "analysis_start_date" not in st.session_state:
    st.session_state.analysis_start_date = None

if "analysis_end_date" not in st.session_state:
    st.session_state.analysis_end_date = None

if "email_completed" not in st.session_state:
    st.session_state.email_completed = False

if "email_report" not in st.session_state:
    st.session_state.email_report = ""


# ============================================================
# GOOGLE AUTHENTICATION
# ============================================================

try:
    logged_in = st.user.is_logged_in
except Exception:
    logged_in = False


if not logged_in:

    st.title("🔐 Browser Forensics")

    st.markdown(
        """
        ## Sign in required

        This Browser Forensics application requires
        Google authentication.
        """
    )

    st.button(
        "🔵 Sign in with Google",
        on_click=st.login,
        use_container_width=True
    )

    st.info(
        "Sign in with your Google account to continue."
    )

    st.stop()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.success(
        "✅ Google account authenticated"
    )

    user_name = getattr(
        st.user,
        "name",
        "Google User"
    )

    user_email = getattr(
        st.user,
        "email",
        ""
    )

    st.markdown(
        f"### 👤 {user_name}"
    )

    if user_email:
        st.caption(user_email)

    st.divider()

    st.button(
        "🚪 Sign out",
        on_click=st.logout,
        use_container_width=True
    )

    st.divider()

    st.caption(
        "AI-Based Browser Forensics"
    )

    st.caption(
        "Multi-browser history + phishing URL analysis"
    )


# ============================================================
# HEADER
# ============================================================

st.title(
    "🌐 Browser Forensics"
)

st.write(
    "Extract browser history and analyze visited URLs "
    "for phishing and suspicious activity."
)


# ============================================================
# FIND RESULT FILE
# ============================================================

def find_result_file():

    possible_files = [
        RESULT_FILE_BROWSER,
        RESULT_FILE_ROOT
    ]

    for file_path in possible_files:

        if os.path.isfile(file_path):
            return file_path

    return None


# ============================================================
# NORMALIZE STATUS
# ============================================================

def normalize_status_column(df):

    df = df.copy()

    # --------------------------------------------------------
    # Find existing status column
    # --------------------------------------------------------

    if "Status" not in df.columns:

        possible_columns = [
            "Prediction",
            "Result",
            "Label",
            "Classification",
            "Risk",
            "Verdict"
        ]

        for column in possible_columns:

            if column in df.columns:

                df["Status"] = (
                    df[column]
                    .astype(str)
                    .str.strip()
                    .str.upper()
                )

                break

    # --------------------------------------------------------
    # If no status exists
    # --------------------------------------------------------

    if "Status" not in df.columns:

        df["Status"] = "UNKNOWN"

    # --------------------------------------------------------
    # Normalize values
    # --------------------------------------------------------

    df["Status"] = (
        df["Status"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    df["Status"] = df["Status"].replace(
        {
            "NOT SAFE": "PHISHING",
            "UNSAFE": "PHISHING",
            "MALICIOUS": "PHISHING",
            "MALWARE": "PHISHING",
            "PHISH": "PHISHING",

            "SAFE": "BENIGN",
            "LEGITIMATE": "BENIGN",
            "NORMAL": "BENIGN",

            "RISKY": "SUSPICIOUS",
            "WARNING": "SUSPICIOUS"
        }
    )

    return df


# ============================================================
# LOCAL URL RISK ANALYSIS
#
# Used only when browser_analysis.py does not create
# suspicious_urls_v3.csv.
# ============================================================

def local_url_analysis(history_df):

    df = history_df.copy()

    if "URL" not in df.columns:

        return pd.DataFrame()

    results = []

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "update",
        "password",
        "signin",
        "sign-in",
        "wallet",
        "bank",
        "confirm",
        "credential",
        "unlock",
        "suspended",
        "recover",
        "payment"
    ]

    suspicious_domains = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".top",
        ".xyz",
        ".click",
        ".work",
        ".zip",
        ".mov"
    ]

    for _, row in df.iterrows():

        url = str(
            row.get("URL", "")
        ).strip()

        lower_url = url.lower()

        score = 0
        reasons = []

        # ----------------------------------------------------
        # HTTPS
        # ----------------------------------------------------

        if lower_url.startswith("http://"):

            score += 15

            reasons.append(
                "Uses HTTP instead of HTTPS"
            )

        # ----------------------------------------------------
        # IP address
        # ----------------------------------------------------

        if "://" in lower_url:

            host_part = (
                lower_url
                .split("://", 1)[1]
                .split("/", 1)[0]
            )

            host_only = host_part.split(":")[0]

            parts = host_only.split(".")

            if (
                len(parts) == 4
                and all(
                    part.isdigit()
                    for part in parts
                )
            ):

                score += 30

                reasons.append(
                    "Uses an IP address instead of a domain"
                )

        # ----------------------------------------------------
        # Suspicious words
        # ----------------------------------------------------

        found_words = []

        for word in suspicious_words:

            if word in lower_url:

                found_words.append(word)

        if found_words:

            score += min(
                30,
                len(found_words) * 8
            )

            reasons.append(
                "Contains security/account-related keywords: "
                + ", ".join(found_words[:5])
            )

        # ----------------------------------------------------
        # Suspicious TLD
        # ----------------------------------------------------

        for tld in suspicious_domains:

            if tld in lower_url:

                score += 20

                reasons.append(
                    f"Uses a higher-risk domain ending: {tld}"
                )

                break

        # ----------------------------------------------------
        # Excessive URL length
        # ----------------------------------------------------

        if len(url) > 180:

            score += 15

            reasons.append(
                "Unusually long URL"
            )

        # ----------------------------------------------------
        # @ symbol
        # ----------------------------------------------------

        if "@" in lower_url:

            score += 25

            reasons.append(
                "Contains @ symbol"
            )

        # ----------------------------------------------------
        # Too many subdomains
        # ----------------------------------------------------

        if "://" in lower_url:

            host = (
                lower_url
                .split("://", 1)[1]
                .split("/", 1)[0]
                .split(":")[0]
            )

            dot_count = host.count(".")

            if dot_count >= 4:

                score += 15

                reasons.append(
                    "Contains many subdomains"
                )

        # ----------------------------------------------------
        # Final classification
        # ----------------------------------------------------

        if score >= 50:

            status = "PHISHING"

        elif score >= 20:

            status = "SUSPICIOUS"

        else:

            status = "BENIGN"

        result = row.to_dict()

        result["Status"] = status

        result["Risk Score"] = score

        if reasons:

            result["Analysis"] = "; ".join(
                reasons
            )

        else:

            result["Analysis"] = (
                "No significant URL risk indicators detected"
            )

        results.append(result)

    return pd.DataFrame(results)


# ============================================================
# CALCULATE STATISTICS
# ============================================================

def calculate_statistics(df):

    if df.empty:

        return (
            0,
            0,
            0,
            0,
            "LOW"
        )

    status = (
        df["Status"]
        .astype(str)
        .str.upper()
        .str.strip()
    )

    total = len(df)

    phishing = int(
        (status == "PHISHING").sum()
    )

    benign = int(
        (status == "BENIGN").sum()
    )

    suspicious = int(
        status.isin(
            [
                "SUSPICIOUS",
                "UNKNOWN"
            ]
        ).sum()
    )

    if phishing >= 5:

        risk = "HIGH"

    elif phishing >= 1:

        risk = "MEDIUM"

    elif suspicious >= 5:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    return (
        total,
        phishing,
        benign,
        suspicious,
        risk
    )


# ============================================================
# RUN BROWSER ANALYSIS
# ============================================================

def run_browser_analysis(
    start_date,
    end_date
):

    env = os.environ.copy()

    env[
        "INVESTIGATION_START_DATE"
    ] = str(start_date)

    env[
        "INVESTIGATION_END_DATE"
    ] = str(end_date)

    env[
        "PYTHONUNBUFFERED"
    ] = "1"

    result = subprocess.run(
        [
            sys.executable,
            "-u",
            BROWSER_ANALYSIS_FILE
        ],
        cwd=BROWSER_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env
    )

    return result


# ============================================================
# RUN EMAIL FORENSICS
# ============================================================

def run_email_forensics():
    """Run the existing email-forensics pipeline and load its report."""

    if not os.path.isdir(EMAIL_PROJECT_DIR):
        st.error("❌ Email forensics folder was not found.")
        st.code(EMAIL_PROJECT_DIR)
        return False

    if not os.path.exists(EMAIL_MAIN):
        st.error("❌ Email main.py was not found.")
        st.code(EMAIL_MAIN)
        return False

    # Remove the previous report so a failed run cannot display stale data.
    if os.path.exists(EMAIL_REPORT):
        try:
            os.remove(EMAIL_REPORT)
        except Exception as error:
            st.warning("Could not remove the previous email forensic report.")
            st.exception(error)

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-u",
                EMAIL_MAIN,
            ],
            cwd=EMAIL_PROJECT_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        if result.stdout:
            with st.expander("📧 Email Forensics Console Output", expanded=True):
                st.code(result.stdout)

        if result.stderr:
            with st.expander("⚠️ Email Forensics Error Output", expanded=True):
                st.code(result.stderr)

        if result.returncode != 0:
            st.error("❌ Email Forensics failed.")
            st.error(f"Return code: {result.returncode}")
            return False

        if not os.path.exists(EMAIL_REPORT):
            st.error("❌ Email analysis finished, but forensic_report.txt was not generated.")
            st.code(EMAIL_REPORT)
            return False

        with open(EMAIL_REPORT, "r", encoding="utf-8", errors="replace") as file:
            report = file.read()

        if not report.strip():
            st.error("❌ Email forensic report is empty.")
            return False

        st.session_state.email_report = report
        st.session_state.email_completed = True
        return True

    except Exception as error:
        st.error("❌ Could not run Email Forensics.")
        st.exception(error)
        return False


# ============================================================
# FORENSIC REPORT
# ============================================================

def create_report(
    df,
    start_date,
    end_date,
    total,
    phishing,
    benign,
    suspicious,
    risk
):

    report = []

    report.append(
        "============================================================"
    )

    report.append(
        "             AI-BASED BROWSER FORENSIC REPORT"
    )

    report.append(
        "============================================================"
    )

    report.append("")

    report.append(
        "INVESTIGATION INFORMATION"
    )

    report.append(
        "------------------------------------------------------------"
    )

    report.append(
        f"Investigation Start : {start_date}"
    )

    report.append(
        f"Investigation End   : {end_date}"
    )

    report.append("")

    report.append(
        "BROWSER FORENSIC SUMMARY"
    )

    report.append(
        "------------------------------------------------------------"
    )

    report.append(
        f"Total URLs          : {total}"
    )

    report.append(
        f"Phishing URLs       : {phishing}"
    )

    report.append(
        f"Benign URLs         : {benign}"
    )

    report.append(
        f"Suspicious URLs     : {suspicious}"
    )

    report.append(
        f"Overall Risk        : {risk}"
    )

    report.append("")

    report.append(
        "URL ANALYSIS RESULTS"
    )

    report.append(
        "------------------------------------------------------------"
    )

    if df.empty:

        report.append(
            "No browser records were found."
        )

    else:

        for index, row in df.iterrows():

            report.append(
                f"Record              : {index + 1}"
            )

            report.append(
                f"Browser             : "
                f"{row.get('Browser', '')}"
            )

            report.append(
                f"URL                 : "
                f"{row.get('URL', '')}"
            )

            report.append(
                f"Title               : "
                f"{row.get('Title', '')}"
            )

            report.append(
                f"Visit Time          : "
                f"{row.get('Visit Time', '')}"
            )

            report.append(
                f"Status              : "
                f"{row.get('Status', '')}"
            )

            if "Confidence" in df.columns:

                report.append(
                    f"Confidence          : "
                    f"{row.get('Confidence', '')}"
                )

            if "Risk Score" in df.columns:

                report.append(
                    f"Risk Score          : "
                    f"{row.get('Risk Score', '')}"
                )

            if "Analysis" in df.columns:

                report.append(
                    f"Analysis            : "
                    f"{row.get('Analysis', '')}"
                )

            report.append(
                "------------------------------------------------------------"
            )

    report.append("")

    report.append(
        "End of Browser Forensic Report"
    )

    return "\n".join(report)



# ============================================================
# COMBINED PDF REPORT
# ============================================================

def generate_combined_pdf(
    output_path,
    browser_df=None,
    browser_report="",
    email_report="",
    start_date_value=None,
    end_date_value=None,
):
    """
    Generate one combined Browser + Email forensic PDF.

    The PDF includes:
      - investigation period
      - browser statistics
      - browser URL findings
      - browser forensic report
      - complete email forensic report
    """

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="AI-Based Browser & Email Forensics Report",
        author="AI-Based Browser & Email Forensics Engine",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CombinedTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        leading=22,
        spaceAfter=8,
    )

    heading_style = ParagraphStyle(
        "CombinedHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        spaceBefore=8,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "CombinedNormal",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "CombinedSmall",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
    )

    story = []

    story.append(
        Paragraph(
            "AI-Based Browser & Email Forensics Report",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Combined Digital Forensic Investigation",
            normal_style,
        )
    )

    if start_date_value is not None and end_date_value is not None:
        story.append(
            Paragraph(
                f"<b>Investigation Period:</b> "
                f"{escape(str(start_date_value))} to "
                f"{escape(str(end_date_value))}",
                normal_style,
            )
        )

    story.append(Spacer(1, 8))

    # ------------------------------------------------------------
    # Browser section
    # ------------------------------------------------------------
    story.append(
        Paragraph(
            "1. Browser Forensics",
            heading_style,
        )
    )

    browser_available = (
        browser_df is not None
        and not browser_df.empty
    )

    if browser_available:
        try:
            browser_copy = normalize_status_column(
                browser_df.copy()
            )

            total, phishing, benign, suspicious, risk = (
                calculate_statistics(browser_copy)
            )

            summary_data = [
                ["Metric", "Result"],
                ["Total URLs", str(total)],
                ["Phishing URLs", str(phishing)],
                ["Benign URLs", str(benign)],
                ["Suspicious / Unknown URLs", str(suspicious)],
                ["Overall Browser Risk", str(risk)],
            ]

            summary_table = Table(
                summary_data,
                colWidths=[85 * mm, 75 * mm],
                repeatRows=1,
            )

            summary_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )

            story.append(summary_table)
            story.append(Spacer(1, 10))

            story.append(
                Paragraph(
                    "Browser URL Findings",
                    styles["Heading3"],
                )
            )

            preferred = [
                "Browser",
                "URL",
                "Title",
                "Status",
                "Confidence",
                "Risk Score",
                "Risk Level",
                "Analysis",
            ]

            columns = [
                col for col in preferred
                if col in browser_copy.columns
            ]

            if not columns:
                columns = list(browser_copy.columns)[:5]

            # Keep the PDF readable. The CSV remains the complete dataset.
            display_df = browser_copy.head(100)

            table_data = [
                [escape(str(col)) for col in columns]
            ]

            for _, row in display_df.iterrows():
                row_values = []
                for col in columns:
                    value = str(row.get(col, ""))
                    if len(value) > 100:
                        value = value[:100] + "..."
                    row_values.append(
                        Paragraph(
                            escape(value),
                            small_style,
                        )
                    )
                table_data.append(row_values)

            if len(columns) <= 3:
                widths = [55 * mm] * len(columns)
            else:
                total_width = 186 * mm
                widths = [total_width / len(columns)] * len(columns)

            details_table = Table(
                table_data,
                colWidths=widths,
                repeatRows=1,
            )

            details_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 6),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 3),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )

            story.append(details_table)

            if len(browser_copy) > 100:
                story.append(
                    Spacer(1, 5)
                )
                story.append(
                    Paragraph(
                        f"Showing the first 100 of {len(browser_copy)} "
                        "browser records in the PDF. The complete dataset "
                        "is available through the CSV download.",
                        small_style,
                    )
                )

            story.append(PageBreak())

            story.append(
                Paragraph(
                    "Browser Forensic Report",
                    heading_style,
                )
            )

            browser_report_text = browser_report or create_report(
                browser_copy,
                start_date_value,
                end_date_value,
                total,
                phishing,
                benign,
                suspicious,
                risk,
            )

            for block in str(browser_report_text).split("\n"):
                if block.strip():
                    story.append(
                        Preformatted(
                            block,
                            ParagraphStyle(
                                "BrowserPre",
                                fontName="Courier",
                                fontSize=6.5,
                                leading=8,
                            ),
                        )
                    )

        except Exception as browser_error:
            story.append(
                Paragraph(
                    "<b>Browser report could not be formatted:</b> "
                    + escape(str(browser_error)),
                    normal_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "Browser analysis was not completed in this session.",
                normal_style,
            )
        )

    story.append(PageBreak())

    # ------------------------------------------------------------
    # Email section
    # ------------------------------------------------------------
    story.append(
        Paragraph(
            "2. Email Forensics",
            heading_style,
        )
    )

    if email_report and str(email_report).strip():
        story.append(
            Paragraph(
                "The following report was generated by the existing "
                "Email Forensics pipeline.",
                normal_style,
            )
        )

        for block in str(email_report).split("\n"):
            if block.strip():
                story.append(
                    Preformatted(
                        block,
                        ParagraphStyle(
                            "EmailPre",
                            fontName="Courier",
                            fontSize=7,
                            leading=9,
                        ),
                    )
                )
    else:
        story.append(
            Paragraph(
                "Email forensics was not completed in this session.",
                normal_style,
            )
        )

    story.append(PageBreak())

    # ------------------------------------------------------------
    # Final combined status
    # ------------------------------------------------------------
    story.append(
        Paragraph(
            "3. Combined Investigation Status",
            heading_style,
        )
    )

    browser_status = (
        "Completed"
        if browser_available
        else "Not completed"
    )

    email_status = (
        "Completed"
        if email_report and str(email_report).strip()
        else "Not completed"
    )

    final_data = [
        ["Module", "Status"],
        ["Browser Forensics", browser_status],
        ["Email Forensics", email_status],
    ]

    final_table = Table(
        final_data,
        colWidths=[85 * mm, 75 * mm],
        repeatRows=1,
    )

    final_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(final_table)
    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Generated by the AI-Based Browser & Email Forensics Engine.",
            normal_style,
        )
    )

    document.build(story)

    return output_path


# ============================================================
# INVESTIGATION PERIOD
# ============================================================

st.divider()

st.header(
    "📅 Investigation Period"
)

today = date.today()

default_start = (
    today - timedelta(days=7)
)

col1, col2 = st.columns(2)

with col1:

    start_date = st.date_input(
        "Start Date",
        value=default_start
    )

with col2:

    end_date = st.date_input(
        "End Date",
        value=today
    )


# ============================================================
# DATE VALIDATION
# ============================================================

if start_date > end_date:

    st.error(
        "❌ Start Date cannot be after End Date."
    )

    st.stop()


# ============================================================
# BROWSER ANALYSIS - CLOUD SAFE UPLOAD WORKFLOW
# ============================================================

st.divider()

st.header("🔎 Browser Analysis")

st.info(
    "☁️ Because this application runs online, it cannot directly read "
    "Chrome/Edge history from your computer. Upload the browser history "
    "CSV exported/generated on your computer, then run the forensic analysis."
)

uploaded_history = st.file_uploader(
    "📤 Upload Browser History CSV",
    type=["csv"],
    help=(
        "Upload browser_history.csv or another browser-history CSV containing "
        "a URL column. The file is processed only for this investigation."
    ),
)

if uploaded_history is not None:
    st.success(
        f"✅ File selected: {uploaded_history.name}"
    )

    try:
        preview_df = pd.read_csv(uploaded_history)
        st.caption(
            f"Preview: {len(preview_df)} records, "
            f"{len(preview_df.columns)} columns"
        )
        st.dataframe(
            preview_df.head(10),
            use_container_width=True,
            hide_index=True,
        )
    except Exception as preview_error:
        st.error("❌ The uploaded CSV could not be read.")
        st.exception(preview_error)

if st.button(
    "🔎 Analyze Uploaded Browser History",
    type="primary",
    use_container_width=True,
    disabled=uploaded_history is None,
):

    st.session_state.analysis_complete = False
    st.session_state.browser_results = None
    st.session_state.analysis_start_date = start_date
    st.session_state.analysis_end_date = end_date

    try:
        # Re-read from the beginning because the uploader object may have
        # been consumed by the preview above.
        uploaded_history.seek(0)
        history_df = pd.read_csv(uploaded_history)

        if history_df.empty:
            st.error("❌ The uploaded browser history CSV is empty.")
            st.stop()

        # --------------------------------------------------------
        # Normalize common browser-history column names.
        # --------------------------------------------------------
        rename_map = {}
        for column in history_df.columns:
            normalized = str(column).strip().lower().replace("_", " ")

            if normalized in ["url", "web url", "website url", "link"]:
                rename_map[column] = "URL"
            elif normalized in ["title", "page title", "website title"]:
                rename_map[column] = "Title"
            elif normalized in [
                "visit time",
                "visited time",
                "visit timestamp",
                "timestamp",
                "datetime",
                "date time",
            ]:
                rename_map[column] = "Visit Time"
            elif normalized in ["browser", "browser name"]:
                rename_map[column] = "Browser"

        history_df = history_df.rename(columns=rename_map)

        if "URL" not in history_df.columns:
            st.error(
                "❌ The uploaded CSV does not contain a URL column. "
                "Please upload a browser history CSV containing URL/address data."
            )
            st.write("Detected columns:", list(history_df.columns))
            st.stop()

        # --------------------------------------------------------
        # Filter the investigation period when a visit-time column exists.
        # If the date column cannot be parsed, analyze all uploaded records.
        # --------------------------------------------------------
        filtered_df = history_df.copy()

        if "Visit Time" in filtered_df.columns:
            parsed_time = pd.to_datetime(
                filtered_df["Visit Time"],
                errors="coerce",
            )

            valid_time_count = int(parsed_time.notna().sum())

            if valid_time_count > 0:
                start_timestamp = pd.Timestamp(start_date)
                end_timestamp = pd.Timestamp(end_date) + pd.Timedelta(days=1)

                date_filtered = filtered_df[
                    (parsed_time >= start_timestamp)
                    & (parsed_time < end_timestamp)
                ].copy()

                if not date_filtered.empty:
                    filtered_df = date_filtered
                else:
                    st.warning(
                        "⚠️ No records matched the selected date range. "
                        "The uploaded records will be analyzed instead."
                    )

        # --------------------------------------------------------
        # Run the same URL-risk logic used by the existing project.
        # --------------------------------------------------------
        with st.spinner(
            "🔬 Analyzing uploaded browser history for suspicious and phishing URLs..."
        ):
            result_df = local_url_analysis(filtered_df)

        if result_df.empty:
            st.error("❌ No usable URL records were found in the uploaded file.")
            st.stop()

        result_df = normalize_status_column(result_df)

        # Save the generated result in the same location expected by the
        # existing report/download workflow.
        result_df.to_csv(
            RESULT_FILE_ROOT,
            index=False,
        )
        result_df.to_csv(
            RESULT_FILE_BROWSER,
            index=False,
        )

        # Save the uploaded history as the current investigation history.
        filtered_df.to_csv(
            HISTORY_FILE,
            index=False,
        )

        st.session_state.browser_results = result_df
        st.session_state.analysis_complete = True
        st.session_state.analysis_start_date = start_date
        st.session_state.analysis_end_date = end_date

        total, phishing, benign, suspicious, risk = calculate_statistics(result_df)

        st.success(
            f"✅ Browser forensic analysis completed: {total} URL records analyzed."
        )

        st.info(
            f"Risk summary — Phishing: {phishing} | "
            f"Suspicious: {suspicious} | Benign: {benign} | "
            f"Overall risk: {risk}"
        )

    except Exception as error:
        st.error("❌ Browser analysis could not be completed.")
        st.exception(error)


# ============================================================
# DISPLAY RESULTS
# ============================================================

if st.session_state.analysis_complete:

    df = st.session_state.browser_results

    if df is None:

        st.warning(
            "No analysis results available."
        )

        st.stop()

    df = normalize_status_column(
        df.copy()
    )

    # ========================================================
    # STATISTICS
    # ========================================================

    (
        total,
        phishing,
        benign,
        suspicious,
        risk
    ) = calculate_statistics(
        df
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    st.divider()

    st.header(
        "📊 Browser Forensic Summary"
    )

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric(
        "🌐 Total URLs",
        total
    )

    c2.metric(
        "🔴 Phishing",
        phishing
    )

    c3.metric(
        "🟢 Benign",
        benign
    )

    c4.metric(
        "🟠 Suspicious",
        suspicious
    )

    c5.metric(
        "⚠️ Risk",
        risk
    )

    st.info(
        f"📅 Investigation period: "
        f"{st.session_state.analysis_start_date} "
        f"→ "
        f"{st.session_state.analysis_end_date}"
    )

    # ========================================================
    # RISK MESSAGE
    # ========================================================

    if risk == "HIGH":

        st.error(
            "🔴 HIGH RISK: Multiple phishing or suspicious URLs detected."
        )

    elif risk == "MEDIUM":

        st.warning(
            "🟠 MEDIUM RISK: Potentially harmful browser activity detected."
        )

    else:

        st.success(
            "🟢 LOW RISK: No significant phishing activity detected."
        )

    # ========================================================
    # PHISHING URLS
    # ========================================================

    phishing_df = df[
        df["Status"]
        .astype(str)
        .str.upper()
        .str.strip()
        == "PHISHING"
    ]

    st.divider()

    st.header(
        "🔴 Detected Phishing URLs"
    )

    if phishing_df.empty:

        st.success(
            "No phishing URLs detected."
        )

    else:

        st.dataframe(
            phishing_df,
            use_container_width=True,
            hide_index=True
        )

    # ========================================================
    # SUSPICIOUS URLS
    # ========================================================

    suspicious_df = df[
        df["Status"]
        .astype(str)
        .str.upper()
        .str.strip()
        .isin(
            [
                "SUSPICIOUS",
                "UNKNOWN"
            ]
        )
    ]

    st.divider()

    st.header(
        "🟠 Suspicious URLs"
    )

    if suspicious_df.empty:

        st.success(
            "No suspicious URLs detected."
        )

    else:

        st.dataframe(
            suspicious_df,
            use_container_width=True,
            hide_index=True
        )

    # ========================================================
    # DOWNLOAD CSV
    # ========================================================

    st.divider()

    st.header(
        "📥 Download Results"
    )

    csv_data = df.to_csv(
        index=False
    )

    st.download_button(
        label="⬇️ Download Browser Analysis CSV",
        data=csv_data,
        file_name="browser_forensic_results.csv",
        mime="text/csv",
        use_container_width=True
    )

    # ========================================================
    # FORENSIC REPORT
    # ========================================================

    st.divider()

    st.header(
        "📄 Browser Forensic Report"
    )

    report_text = create_report(
        df,
        st.session_state.analysis_start_date,
        st.session_state.analysis_end_date,
        total,
        phishing,
        benign,
        suspicious,
        risk
    )

    st.text_area(
        "Forensic Report",
        report_text,
        height=500
    )

    st.download_button(
        label="⬇️ Download Browser Forensic Report",
        data=report_text,
        file_name="browser_forensic_report.txt",
        mime="text/plain",
        use_container_width=True
    )


# ============================================================
# EMAIL FORENSICS
# ============================================================

st.divider()

st.header(
    "📧 Email Forensics"
)

st.write(
    "Run the existing email-forensics pipeline and combine its results with the browser investigation."
)

if st.button(
    "📧 Run Email Forensics",
    type="primary",
    use_container_width=True,
):

    st.session_state.email_completed = False
    st.session_state.email_report = ""

    if run_email_forensics():
        st.success("✅ Email forensic analysis completed successfully.")

if st.session_state.email_completed:

    st.subheader("📄 Email Forensic Report")

    st.text_area(
        "Email Forensic Report",
        st.session_state.email_report,
        height=500,
    )

    st.download_button(
        label="⬇️ Download Email Forensic Report",
        data=st.session_state.email_report,
        file_name="email_forensic_report.txt",
        mime="text/plain",
        use_container_width=True,
    )

    # --------------------------------------------------------
    # COMBINED PDF
    # --------------------------------------------------------
    if st.session_state.analysis_complete:
        st.divider()
        st.subheader("📄 Combined Browser + Email Report")

        if st.button(
            "📄 Generate Combined PDF Report",
            type="primary",
            use_container_width=True,
        ):
            try:
                with st.spinner(
                    "Generating combined Browser + Email forensic PDF..."
                ):
                    browser_df_for_pdf = (
                        st.session_state.browser_results.copy()
                        if st.session_state.browser_results is not None
                        else None
                    )

                    browser_report_for_pdf = ""

                    if browser_df_for_pdf is not None and not browser_df_for_pdf.empty:
                        browser_df_for_pdf = normalize_status_column(
                            browser_df_for_pdf
                        )

                        (
                            pdf_total,
                            pdf_phishing,
                            pdf_benign,
                            pdf_suspicious,
                            pdf_risk,
                        ) = calculate_statistics(
                            browser_df_for_pdf
                        )

                        browser_report_for_pdf = create_report(
                            browser_df_for_pdf,
                            st.session_state.analysis_start_date,
                            st.session_state.analysis_end_date,
                            pdf_total,
                            pdf_phishing,
                            pdf_benign,
                            pdf_suspicious,
                            pdf_risk,
                        )

                    generate_combined_pdf(
                        COMBINED_PDF,
                        browser_df_for_pdf,
                        browser_report_for_pdf,
                        st.session_state.email_report,
                        st.session_state.analysis_start_date,
                        st.session_state.analysis_end_date,
                    )

                with open(
                    COMBINED_PDF,
                    "rb",
                ) as pdf_file:
                    pdf_bytes = pdf_file.read()

                st.success(
                    "✅ Combined Browser + Email PDF generated successfully."
                )

                st.download_button(
                    label="⬇️ Download Combined Forensic PDF",
                    data=pdf_bytes,
                    file_name="combined_forensic_report.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )

            except Exception as pdf_error:
                st.error(
                    "❌ Could not generate the combined forensic PDF."
                )
                st.exception(pdf_error)

    # Show the combined status when both investigations are complete.
    if st.session_state.analysis_complete:
        st.success(
            "🔗 Browser + Email Forensics are both available in this investigation."
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🌐 AI-Based Browser Forensics Engine | "
    "Google authenticated | "
    "Multi-browser history and phishing URL analysis"
)
