import os
import sys
import subprocess
import ipaddress
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
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
    st.title("🔐 Browser & Email Forensics")

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

st.title("🌐 AI-Based Browser & Email Forensics")

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

        if result.stdout:
            with st.expander("Email console output"):
                st.code(result.stdout)

        if result.stderr:
            with st.expander("Email technical details"):
                st.code(result.stderr)

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

def generate_combined_pdf(
    browser_df,
    browser_report,
    email_report,
    start_date,
    end_date,
):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import (
            getSampleStyleSheet,
            ParagraphStyle,
        )
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Preformatted,
        )
        from xml.sax.saxutils import escape

    except ImportError as error:
        raise RuntimeError(
            "ReportLab is required. Add reportlab to requirements.txt."
        ) from error

    document = SimpleDocTemplate(
        str(COMBINED_PDF),
        pagesize=A4,
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="Browser and Email Forensic Report",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ForensicTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=17,
        leading=21,
        spaceAfter=12,
    )

    heading_style = styles["Heading2"]

    report_style = ParagraphStyle(
        "ReportText",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7,
        leading=9,
        wordWrap="CJK",
    )

    story = [
        Paragraph(
            "AI-Based Browser & Email Forensics Report",
            title_style,
        ),
        Paragraph(
            "Investigation period: "
            + escape(str(start_date))
            + " to "
            + escape(str(end_date)),
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph(
            "1. Browser Forensics",
            heading_style,
        ),
        Preformatted(
            browser_report,
            report_style,
        ),
        Spacer(1, 16),
        Paragraph(
            "2. Email Forensics",
            heading_style,
        ),
        Preformatted(
            email_report,
            report_style,
        ),
    ]

    document.build(story)

    return COMBINED_PDF


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
    "Upload an exported browser-history CSV file. "
    "The CSV should include a URL column and preferably a Visit Time column."
)

browser_upload = st.file_uploader(
    "Upload Browser History CSV",
    type=["csv"],
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
                "Upload a browser-history CSV before running the analysis."
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

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("🌐 Total URLs", total)
    c2.metric("🔴 Phishing", phishing)
    c3.metric("🟢 Benign", benign)
    c4.metric("🟠 Suspicious", suspicious)
    c5.metric("⚠️ Risk", risk)

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
    st.subheader("🔴 Detected Phishing URLs")

    phishing_df = df[
        df["Status"].astype(str).str.upper() == "PHISHING"
    ]

    if phishing_df.empty:
        st.success("No URLs were classified as phishing.")
    else:
        st.dataframe(
            phishing_df,
            use_container_width=True,
            hide_index=True,
        )

    st.divider()
    st.subheader("🟠 Suspicious URLs")

    suspicious_df = df[
        df["Status"].astype(str).str.upper().isin(
            ["SUSPICIOUS", "UNKNOWN"]
        )
    ]

    if suspicious_df.empty:
        st.success("No URLs were classified as suspicious.")
    else:
        st.dataframe(
            suspicious_df,
            use_container_width=True,
            hide_index=True,
        )

    st.divider()
    st.subheader("📥 Download Browser Results")

    st.download_button(
        "⬇️ Download Browser Analysis CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="browser_forensic_results.csv",
        mime="text/csv",
        use_container_width=True,
    )

    browser_report = create_report(
        df,
        st.session_state.analysis_start_date,
        st.session_state.analysis_end_date,
        total,
        phishing,
        benign,
        suspicious,
        risk,
    )

    st.divider()
    st.subheader("📄 Browser Forensic Report")

    st.text_area(
        "Browser Forensic Report",
        browser_report,
        height=400,
    )

    st.download_button(
        "⬇️ Download Browser Forensic Report",
        data=browser_report.encode("utf-8"),
        file_name="browser_forensic_report.txt",
        mime="text/plain",
        use_container_width=True,
    )


# ============================================================
# EMAIL FORENSICS
# ============================================================

st.divider()
st.header("📧 Email Forensics")

st.write(
    "Upload an email evidence file in .eml format."
)

email_upload = st.file_uploader(
    "Upload Email Evidence (.eml)",
    type=["eml"],
    key="email_evidence_upload",
)

if st.button(
    "📧 Run Email Forensics",
    type="primary",
    use_container_width=True,
):
    st.session_state.email_completed = False
    st.session_state.email_report = ""

    if email_upload is None:
        st.error("Upload an .eml file before running email forensics.")

    elif not EMAIL_MAIN.is_file():
        st.error("Email analysis script was not found.")
        st.code(str(EMAIL_MAIN))

    else:
        try:
            EMAIL_INPUT_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            EMAIL_INPUT_FILE.write_bytes(
                email_upload.getvalue()
            )

            with st.spinner("Analyzing email evidence..."):
                success = run_email_forensics()

            if success:
                st.success(
                    "✅ Email forensic analysis completed successfully."
                )

        except Exception as error:
            st.error("Email forensic analysis failed.")
            st.exception(error)


# ============================================================
# DISPLAY EMAIL REPORT
# ============================================================

if st.session_state.email_completed:
    st.subheader("📄 Email Forensic Report")

    st.text_area(
        "Email Forensic Report",
        st.session_state.email_report,
        height=400,
    )

    st.download_button(
        "⬇️ Download Email Forensic Report",
        data=st.session_state.email_report.encode("utf-8"),
        file_name="email_forensic_report.txt",
        mime="text/plain",
        use_container_width=True,
    )


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

else:
    st.info(
        "Complete both browser and email analysis to generate "
        "the combined PDF report."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🌐 AI-Based Browser & Email Forensics Engine | "
    "Browser History Analysis | Phishing URL Detection | "
    "Email Forensics"
)
