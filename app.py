import os
import sys
import subprocess
from datetime import date, timedelta

import pandas as pd
import streamlit as st


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
    "history.csv"
)

RESULT_FILE_BROWSER = os.path.join(
    BROWSER_DIR,
    "suspicious_urls_v3.csv"
)

RESULT_FILE_ROOT = os.path.join(
    APP_DIR,
    "suspicious_urls_v3.csv"
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
# BROWSER ANALYSIS
# ============================================================

st.divider()

st.header(
    "🔎 Browser Analysis"
)

if st.button(
    "🔎 Run Browser Analysis",
    type="primary",
    use_container_width=True
):

    st.session_state.analysis_complete = False

    st.session_state.browser_results = None

    st.session_state.analysis_start_date = (
        start_date
    )

    st.session_state.analysis_end_date = (
        end_date
    )

    # --------------------------------------------------------
    # CHECK FILES
    # --------------------------------------------------------

    if not os.path.isdir(BROWSER_DIR):

        st.error(
            "❌ Browser folder was not found."
        )

        st.code(
            BROWSER_DIR
        )

        st.stop()

    if not os.path.isfile(
        BROWSER_ANALYSIS_FILE
    ):

        st.error(
            "❌ browser_analysis.py was not found."
        )

        st.code(
            BROWSER_ANALYSIS_FILE
        )

        st.stop()

    # --------------------------------------------------------
    # REMOVE OLD RESULT
    # --------------------------------------------------------

    old_result = find_result_file()

    if old_result:

        try:
            os.remove(old_result)
        except Exception:
            pass

    # --------------------------------------------------------
    # RUN
    # --------------------------------------------------------

    with st.spinner(
        "🌐 Extracting browser history and analyzing URLs..."
    ):

        result = run_browser_analysis(
            start_date,
            end_date
        )

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # DO NOT immediately fail on return code 1.
    #
    # browser_analysis.py may return 1 because its trained
    # model is missing while still successfully creating
    # history.csv / suspicious_urls_v3.csv.
    # --------------------------------------------------------

    result_file = find_result_file()

    history_exists = os.path.isfile(
        HISTORY_FILE
    )

    # --------------------------------------------------------
    # SHOW OUTPUT ONLY IF NEEDED
    # --------------------------------------------------------

    if result.stdout:

        with st.expander(
            "🌐 Browser Analysis Output",
            expanded=False
        ):

            st.code(
                result.stdout
            )

    # --------------------------------------------------------
    # IF RESULT EXISTS, CONTINUE
    # --------------------------------------------------------

    if result_file:

        try:

            result_df = pd.read_csv(
                result_file
            )

            result_df = normalize_status_column(
                result_df
            )

            st.session_state.browser_results = (
                result_df
            )

            st.session_state.analysis_complete = True

            st.session_state.analysis_start_date = (
                start_date
            )

            st.session_state.analysis_end_date = (
                end_date
            )

            if history_exists:

                st.success(
                    "✅ Browser history extraction completed."
                )

            st.success(
                "✅ Browser URL analysis completed."
            )

            # ------------------------------------------------
            # Do not show the model error to the user if
            # usable results were successfully generated.
            # ------------------------------------------------

        except Exception as error:

            st.error(
                "❌ The analysis result was created "
                "but could not be read."
            )

            st.exception(error)

            st.stop()

    else:

        # ----------------------------------------------------
        # NO RESULT FILE
        #
        # Try local analysis directly from history.csv.
        # ----------------------------------------------------

        if history_exists:

            try:

                history_df = pd.read_csv(
                    HISTORY_FILE
                )

                # --------------------------------------------
                # Filter selected investigation period
                # --------------------------------------------

                if "Visit Time" in history_df.columns:

                    history_df["Parsed Time"] = (
                        pd.to_datetime(
                            history_df["Visit Time"],
                            errors="coerce"
                        )
                    )

                    start_timestamp = pd.Timestamp(
                        start_date
                    )

                    end_timestamp = (
                        pd.Timestamp(end_date)
                        + pd.Timedelta(days=1)
                    )

                    filtered_df = history_df[
                        (
                            history_df["Parsed Time"]
                            >= start_timestamp
                        )
                        &
                        (
                            history_df["Parsed Time"]
                            < end_timestamp
                        )
                    ].copy()

                    if filtered_df.empty:

                        filtered_df = history_df.copy()

                else:

                    filtered_df = history_df.copy()

                # --------------------------------------------
                # Local URL analysis
                # --------------------------------------------

                fallback_df = local_url_analysis(
                    filtered_df
                )

                if not fallback_df.empty:

                    fallback_df = (
                        normalize_status_column(
                            fallback_df
                        )
                    )

                    # ----------------------------------------
                    # Save fallback result
                    # ----------------------------------------

                    fallback_df.to_csv(
                        RESULT_FILE_BROWSER,
                        index=False
                    )

                    st.session_state.browser_results = (
                        fallback_df
                    )

                    st.session_state.analysis_complete = True

                    st.session_state.analysis_start_date = (
                        start_date
                    )

                    st.session_state.analysis_end_date = (
                        end_date
                    )

                    st.success(
                        "✅ Browser history extracted and "
                        "local URL-risk analysis completed."
                    )

                else:

                    st.error(
                        "❌ Browser history was found, "
                        "but no URL records were available."
                    )

                    st.stop()

            except Exception as error:

                st.error(
                    "❌ Browser analysis could not be completed."
                )

                st.exception(error)

                if result.stderr:

                    with st.expander(
                        "Technical Error Details",
                        expanded=True
                    ):

                        st.code(
                            result.stderr
                        )

                st.stop()

        else:

            st.error(
                "❌ Browser analysis failed and no "
                "history.csv was generated."
            )

            if result.stderr:

                with st.expander(
                    "Technical Error Details",
                    expanded=True
                ):

                    st.code(
                        result.stderr
                    )

            st.stop()


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
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🌐 AI-Based Browser Forensics Engine | "
    "Google authenticated | "
    "Multi-browser history and phishing URL analysis"
)