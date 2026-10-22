import os
import sys
import subprocess
from datetime import date, timedelta
from urllib.parse import urlparse
from pathlib import Path

import pandas as pd
import streamlit as st


# ============================================================
# STREAMLIT CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI-Based Browser & Email Forensics",
    page_icon="🌐",
    layout="wide",
)

# ============================================================
# PROJECT PATHS
# ============================================================

APP_DIR = Path(__file__).resolve().parent

BROWSER_DIR = APP_DIR / "browser"
HISTORY_FILE = BROWSER_DIR / "history.csv"

BROWSER_SCRIPT = BROWSER_DIR / "browser_analysis.py"
PHISHING_SCRIPT = BROWSER_DIR / "suspicious_urls.py"

BROWSER_OUTPUTS = [
    BROWSER_DIR / "suspicious_urls_v3.csv",
    BROWSER_DIR / "browser_forensics_final.csv",
    APP_DIR / "browser_forensics_final.csv",
]

EMAIL_DIR = APP_DIR / "email_forensics_project"
EMAIL_MAIN = EMAIL_DIR / "main.py"
EMAIL_INPUT_DIR = EMAIL_DIR / "emails"
EMAIL_INPUT_FILE = EMAIL_INPUT_DIR / "gmail_message.eml"
EMAIL_REPORT = EMAIL_DIR / "reports" / "forensic_report.txt"

COMBINED_PDF = APP_DIR / "combined_forensic_report.pdf"


# ============================================================
# SESSION STATE
# ============================================================

DEFAULTS = {
    "browser_results": None,
    "browser_complete": False,
    "email_report": "",
    "email_complete": False,
    "start_date": None,
    "end_date": None,
}

for key, value in DEFAULTS.items():
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

    st.info(
        "Sign in with Google to access the forensic analysis dashboard."
    )

    try:
        st.button(
            "🔵 Sign in with Google",
            on_click=st.login,
            use_container_width=True,
        )
    except Exception:
        st.error(
            "Google authentication is not configured correctly. "
            "Check the Streamlit authentication settings."
        )

    st.stop()


# ============================================================
# HEADER AND SIDEBAR
# ============================================================

with st.sidebar:
    st.success("Google account authenticated")

    st.write(
        f"👤 {getattr(st.user, 'name', 'Google User')}"
    )

    user_email = getattr(st.user, "email", "")
    if user_email:
        st.caption(user_email)

    st.button(
        "🚪 Sign out",
        on_click=st.logout,
        use_container_width=True,
    )

    st.divider()
    st.caption("AI-Based Digital Forensics Engine")


st.title("🌐 AI-Based Browser & Email Forensics")

st.write(
    "Analyze browser-history records, identify potentially "
    "phishing URLs, examine email evidence, and generate reports."
)

st.warning(
    "Cloud applications cannot directly access browser history "
    "stored on your personal computer. Upload exported browser "
    "history as a CSV file to analyze it."
)


# ============================================================
# COMMON FUNCTIONS
# ============================================================

def normalize_columns(df):
    """Standardize common browser-history column names."""

    df = df.copy()

    rename_map = {}

    for column in df.columns:
        cleaned = str(column).strip().lower()

        if cleaned in ["url", "website", "web address", "link"]:
            rename_map[column] = "URL"

        elif cleaned in [
            "visit time",
            "timestamp",
            "visit date",
            "date",
            "last visit time",
        ]:
            rename_map[column] = "Visit Time"

        elif cleaned in ["title", "page title", "website title"]:
            rename_map[column] = "Title"

        elif cleaned in ["browser", "browser name"]:
            rename_map[column] = "Browser"

    df = df.rename(columns=rename_map)

    return df


def normalize_status_column(df):
    """Standardize prediction labels."""

    df = df.copy()

    if "Status" not in df.columns:
        for column in [
            "Prediction",
            "Result",
            "Classification",
            "Label",
            "Verdict",
        ]:
            if column in df.columns:
                df["Status"] = df[column]
                break

    if "Status" not in df.columns:
        df["Status"] = "UNKNOWN"

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

    df["Status"] = (
        df["Status"]
        .astype(str)
        .str.strip()
        .str.upper()
        .replace(status_map)
    )

    return df


# ============================================================
# FALLBACK URL ANALYSIS
# ============================================================

def local_url_analysis(history_df):
    """
    Basic URL-risk heuristic used only when the existing
    model pipeline does not generate a usable output.

    This is NOT an ML-model prediction.
    """

    df = normalize_columns(history_df)

    if "URL" not in df.columns:
        raise ValueError(
            "The uploaded CSV must contain a URL column."
        )

    results = []

    suspicious_words = [
        "login",
        "verify",
        "account",
        "password",
        "signin",
        "wallet",
        "bank",
        "confirm",
        "credential",
        "suspended",
        "payment",
        "recover",
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

        score = 0
        reasons = []

        parsed = urlparse(
            url if "://" in url else "http://" + url
        )

        host = parsed.hostname or ""
        lower_url = url.lower()

        if lower_url.startswith("http://"):
            score += 10
            reasons.append("Uses HTTP")

        if "@" in parsed.netloc:
            score += 25
            reasons.append("Contains @ in the URL authority")

        try:
            import ipaddress
            ipaddress.ip_address(host)
            score += 30
            reasons.append("Uses an IP address as the host")
        except ValueError:
            pass

        found_words = [
            word for word in suspicious_words
            if word in lower_url
        ]

        if found_words:
            score += min(30, len(found_words) * 8)
            reasons.append(
                "Suspicious keywords: " + ", ".join(found_words[:5])
            )

        if any(host.endswith(tld) for tld in suspicious_tlds):
            score += 15
            reasons.append("Potentially risky domain ending")

        if len(url) > 180:
            score += 10
            reasons.append("Unusually long URL")

        if host.count(".") >= 4:
            score += 10
            reasons.append("Many subdomains")

        if score >= 50:
            status = "PHISHING"
        elif score >= 20:
            status = "SUSPICIOUS"
        else:
            status = "BENIGN"

        result = row.to_dict()
        result["Status"] = status
        result["Risk Score"] = min(score, 100)
        result["Analysis"] = (
            "; ".join(reasons)
            if reasons
            else "No significant URL risk indicators detected"
        )

        results.append(result)

    return pd.DataFrame(results)


# ============================================================
# DATE FILTERING
# ============================================================

def filter_dates(df, start_date, end_date):
    """Filter history records by visit date when available."""

    df = normalize_columns(df)

    if "Visit Time" not in df.columns:
        return df

    parsed_dates = pd.to_datetime(
        df["Visit Time"],
        errors="coerce",
        utc=True,
    )

    start = pd.Timestamp(start_date, tz="UTC")
    end = pd.Timestamp(
        end_date + timedelta(days=1),
        tz="UTC",
    )

    mask = (
        (parsed_dates >= start)
        & (parsed_dates < end)
    )

    filtered = df.loc[mask].copy()

    # Do not silently lose all data when date formats differ.
    if filtered.empty and not df.empty:
        st.warning(
            "No records matched the selected dates. "
            "Check the CSV's Visit Time format. "
            "The analysis will use all uploaded records."
        )
        return df

    return filtered


# ============================================================
# RUN EXISTING BROWSER MODEL PIPELINE
# ============================================================

def run_existing_browser_pipeline():
    """
    Attempt to run the existing project scripts.
    Return a usable CSV DataFrame when one is generated.
    """

    scripts = []

    if BROWSER_SCRIPT.is_file():
        scripts.append(BROWSER_SCRIPT)

    if PHISHING_SCRIPT.is_file():
        scripts.append(PHISHING_SCRIPT)

    for script in scripts:
        # Delete old outputs so stale results are not reused.
        for output in BROWSER_OUTPUTS:
            try:
                if output.exists():
                    output.unlink()
            except OSError:
                pass

        try:
            result = subprocess.run(
                [sys.executable, "-u", str(script)],
                cwd=str(BROWSER_DIR),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
            )

            with st.expander(
                f"Console output: {script.name}",
                expanded=False,
            ):
                if result.stdout:
                    st.code(result.stdout)

                if result.stderr:
                    st.code(result.stderr)

                st.write(
                    f"Exit code: {result.returncode}"
                )

            for output in BROWSER_OUTPUTS:
                if output.is_file():
                    try:
                        result_df = pd.read_csv(output)

                        if (
                            not result_df.empty
                            and "URL" in normalize_columns(
                                result_df
                            ).columns
                        ):
                            return normalize_columns(result_df)

                    except Exception:
                        continue
