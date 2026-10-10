```python
import streamlit as st
import pandas as pd
import os
import subprocess
import sys
import base64
from datetime import datetime, timedelta

# Resolve the actual project folder.
APP_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
NESTED_PROJECT_DIR = os.path.join(APP_FILE_DIR, "email_forensics_project")
PROJECT_DIR = (
    NESTED_PROJECT_DIR
    if os.path.isfile(os.path.join(NESTED_PROJECT_DIR, "main.py"))
    else APP_FILE_DIR
)

if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import importlib.util

PDF_MODULE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "email_forensics_project",
    "reports",
    "report",
    "pdf_generator.py"
)

if not os.path.isfile(PDF_MODULE_PATH):
    PDF_MODULE_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "reports",
        "report",
        "pdf_generator.py"
    )

if not os.path.isfile(PDF_MODULE_PATH):
    raise FileNotFoundError(
        f"PDF generator not found at: {PDF_MODULE_PATH}"
    )

spec = importlib.util.spec_from_file_location(
    "pdf_generator",
    PDF_MODULE_PATH
)
pdf_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pdf_module)

create_pdf_report = pdf_module.create_pdf_report
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# ==========================================================
# STREAMLIT CONFIGURATION
# ==========================================================
st.set_page_config(
    page_title="AI Browser & Email Forensics",
    page_icon="🔍",
    layout="wide"
)

# ==========================================================
# PROJECT PATHS
# ==========================================================
APP_DIR = PROJECT_DIR

st.write("App directory:", APP_FILE_DIR)
st.write("Project directory:", PROJECT_DIR)
st.write(
    "PDF generator exists:",
    os.path.isfile(
        os.path.join(
            PROJECT_DIR,
            "reports",
            "report",
            "pdf_generator.py"
        )
    )
)

BROWSER_RESULT = os.path.join(APP_DIR, "suspicious_urls_v3.csv")
EMAIL_REPORT_FILE = os.path.join(
    APP_DIR, "reports", "forensic_report.txt"
)
PDF_PATH = os.path.join(APP_DIR, "forensic_report.pdf")
CREDENTIALS_FILE = os.path.join(APP_DIR, "credentials.json")
TOKEN_FILE = os.path.join(APP_DIR, "token.json")
EMAIL_FILE = os.path.join(APP_DIR, "emails", "gmail_message.eml")

# ==========================================================
# GMAIL SETTINGS
# ==========================================================
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]

# ==========================================================
# SESSION STATE
# ==========================================================
if "email_report_text" not in st.session_state:
    st.session_state.email_report_text = ""

if "gmail_messages" not in st.session_state:
    st.session_state.gmail_messages = []

if "gmail_service" not in st.session_state:
    st.session_state.gmail_service = None

if "selected_email_id" not in st.session_state:
    st.session_state.selected_email_id = None

if "selected_email_details" not in st.session_state:
    st.session_state.selected_email_details = None

# ==========================================================
# GMAIL CONNECTION FUNCTION
# ==========================================================
def connect_to_gmail():
    creds = None

    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(
            TOKEN_FILE, SCOPES
        )

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                st.error(
                    "credentials.json was not found in the project folder."
                )
                return None

            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES
            )
            creds = flow.run_local_server(
                port=0,
                access_type="offline",
                prompt="consent"
            )

        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds)
    return service

# ==========================================================
# SEARCH GMAIL FUNCTION
# ==========================================================
def search_gmail(service, email_address, start_date, end_date):
    gmail_start_date = start_date.replace("-", "/")

    # Gmail's "before" date is exclusive.
    # Add one day so the selected end date is included.
    end_datetime = datetime.strptime(end_date, "%Y-%m-%d")
    next_day = end_datetime + timedelta(days=1)
    gmail_end_date = next_day.strftime("%Y/%m/%d")

    query = (
        f"from:{email_address} "
        f"after:{gmail_start_date} "
        f"before:{gmail_end_date}"
    )

    results = service.users().messages().list(
        userId="me",
        q=query,
        maxResults=20
    ).execute()

    return results.get("messages", [])

# ==========================================================
# GET EMAIL DETAILS FUNCTION
# ==========================================================
def get_email_details(service, message_id):
    email_data = service.users().messages().get(
        userId="me",
        id=message_id,
        format="metadata",
        metadataHeaders=["From", "To", "Subject", "Date"]
    ).execute()

    headers = email_data.get("payload", {}).get("headers", [])

    details = {
        "From": "",
        "To": "",
        "Subject": "",
        "Date": ""
    }

    for header in headers:
        name = header.get("name", "")
        value = header.get("value", "")
        if name in details:
            details[name] = value

    return details

# ==========================================================
# DOWNLOAD SELECTED EMAIL FUNCTION
# ==========================================================
def save_selected_email(service, message_id):
    raw_message = service.users().messages().get(
        userId="me",
        id=message_id,
        format="raw"
    ).execute()

    raw_data = raw_message["raw"]
    email_bytes = base64.urlsafe_b64decode(raw_data + "==")

    os.makedirs(os.path.dirname(EMAIL_FILE), exist_ok=True)

    with open(EMAIL_FILE, "wb") as file:
        file.write(email_bytes)

# ==========================================================
# TITLE
# ==========================================================
st.title("🔍 AI-Based Browser & Email Forensics Engine")

# ==========================================================
# BROWSER FORENSICS
# ==========================================================
st.subheader("🌐 Browser Forensics")

if st.button("🔍 Run Browser Analysis"):
    with st.spinner("Running Browser Analysis..."):
        browser_script = os.path.join(
            APP_DIR, "browser", "suspicious_urls.py"
        )

        result = subprocess.run(
            [sys.executable, browser_script],
            cwd=APP_DIR,
            capture_output=True,
            text=True
        )

    if result.returncode == 0:
        st.success("Browser Analysis completed successfully!")
        st.rerun()
    else:
        st.error("Browser Analysis failed.")
        st.code(result.stderr)

# ==========================================================
# LOAD BROWSER RESULTS
# ==========================================================
if os.path.exists(BROWSER_RESULT):
    df = pd.read_csv(BROWSER_RESULT)

    total = len(df)

    if "Status" in df.columns:
        phishing = sum(
            df["Status"].astype(str).str.upper() == "PHISHING"
        )
        benign = sum(
            df["Status"].astype(str).str.upper() == "BENIGN"
        )
    else:
        phishing = 0
        benign = 0
        st.warning("The browser results file has no 'Status' column.")

    if phishing == 0:
        risk_level = "LOW"
    elif phishing <= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total URLs", total)
    col2.metric("🔴 Phishing URLs", phishing)
    col3.metric("🟢 Benign URLs", benign)
    col4.metric("⚠️ Risk Level", risk_level)

    st.divider()
    st.subheader("URL Analysis")

    if "Status" in df.columns:
        status = st.selectbox(
            "Select Result",
            ["All", "PHISHING", "BENIGN"]
        )

        if status == "PHISHING":
            filtered_df = df[
                df["Status"].astype(str).str.upper() == "PHISHING"
            ]
        elif status == "BENIGN":
            filtered_df = df[
                df["Status"].astype(str).str.upper() == "BENIGN"
            ]
        else:
            filtered_df = df
    else:
        filtered_df = df

    st.dataframe(
        filtered_df,
        width="stretch",
        hide_index=True
    )

else:
    st.warning("Browser analysis result not found.")
    st.write("Click 'Run Browser Analysis' first.")

    total = 0
    phishing = 0
    benign = 0
    risk_level = "UNKNOWN"

# ==========================================================
# EMAIL FORENSICS
# ==========================================================
st.divider()
st.subheader("📧 Email Forensics")

st.write(
    "Search Gmail using a sender email address and date range, "
    "select an email, and perform forensic analysis."
)

# ==========================================================
# GMAIL SEARCH INPUTS
# ==========================================================
st.markdown("### 🔎 Gmail Email Search")

email_address = st.text_input(
    "Sender Email Address",
    placeholder="example@gmail.com"
)

col1, col2 = st.columns(2)

with col1:
    start_date = st.date_input("Start Date")

with col2:
    end_date = st.date_input("End Date")

# ==========================================================
# SEARCH BUTTON
# ==========================================================
if st.button("🔎 Search Gmail"):
    if not email_address.strip():
        st.error("Please enter a sender email address.")

    elif start_date > end_date:
        st.error("Start date cannot be after the end date.")

    else:
        try:
            with st.spinner("Connecting to Gmail..."):
                service = connect_to_gmail()

            if service is not None:
                st.session_state.gmail_service = service

                with st.spinner("Searching Gmail..."):
                    messages = search_gmail(
                        service,
                        email_address.strip(),
                        start_date.strftime("%Y-%m-%d"),
                        end_date.strftime("%Y-%m-%d")
                    )

                st.session_state.gmail_messages = messages

                if messages:
                    st.success(
                        f"{len(messages)} matching email(s) found."
                    )
                else:
                    st.warning("No matching emails found.")

        except Exception as error:
            st.error("Gmail search failed.")
            st.exception(error)

# ==========================================================
# DISPLAY MATCHING EMAILS
# ==========================================================
messages = st.session_state.gmail_messages
service = st.session_state.gmail_service

if messages and service is not None:
    st.markdown("### 📬 Matching Emails")

    email_options = []
    email_details_map = {}

    for index, message in enumerate(messages, start=1):
        try:
            details = get_email_details(service, message["id"])
            subject = details["Subject"] or "(No Subject)"

            display_text = (
                f"Email {index} | "
                f"{details['Date']} | "
                f"{subject}"
            )

            email_options.append(display_text)
            email_details_map[display_text] = (
                message["id"],
                details
            )

        except Exception:
            continue

    if email_options:
        selected_option = st.selectbox(
            "Select the email you want to analyze:",
            email_options
        )

        selected_id, selected_details = email_details_map[
            selected_option
        ]

        st.markdown("#### Selected Email Details")
        st.write(f"**From:** {selected_details['From']}")
        st.write(f"**To:** {selected_details['To']}")
        st.write(
            "**Subject:** "
            f"{selected_details['Subject'] or '(No Subject)'}"
        )
        st.write(f"**Date:** {selected_details['Date']}")

        # ==================================================
        # ANALYZE SELECTED EMAIL
        # ==================================================
        if st.button("🔍 Analyze Selected Email"):
            try:
                with st.spinner("Downloading selected email..."):
                    save_selected_email(service, selected_id)

                st.success("Selected email downloaded successfully.")

                with st.spinner("Running Email Forensics..."):
                    result = subprocess.run(
                        [sys.executable, "main.py"],
                        cwd=APP_DIR,
                        capture_output=True,
                        text=True
                    )

                if result.returncode == 0:
                    st.success("Email Forensics completed successfully!")

                    if os.path.exists(EMAIL_REPORT_FILE):
                        with open(
                            EMAIL_REPORT_FILE,
                            "r",
                            encoding="utf-8"
                        ) as file:
                            report = file.read()

                        st.session_state.email_report_text = report

                        st.subheader("📄 Forensic Report")
                        st.text_area(
                            "Email Forensics Report - Preview",
                            report[:10000],
                            height=400
                        )

                        if len(report) > 10000:
                            st.info(
                                "The full email report is saved "
                                "and will be included in the PDF."
                            )
                    else:
                        st.warning(
                            "Email forensic report file was not found."
                        )

                    if result.stdout:
                        with st.expander(
                            "View Email Forensics Console Output"
                        ):
                            st.text(result.stdout)

                else:
                    st.error("Email Forensics failed.")
                    if result.stderr:
                        st.code(result.stderr)

            except Exception as error:
                st.error("Email analysis failed.")
                st.exception(error)

# ==========================================================
# PDF REPORT
# ==========================================================
st.divider()
st.subheader("📄 Generate Forensic Report")

if st.button("📄 Generate PDF Report"):
    try:
        create_pdf_report(
            output_path=PDF_PATH,
            total_urls=total,
            phishing_urls=phishing,
            benign_urls=benign,
            risk_level=risk_level,
            email_report=st.session_state.email_report_text
        )

        st.success("PDF report generated successfully!")

        with open(PDF_PATH, "rb") as pdf_file:
            st.download_button(
                label="⬇️ Download PDF Report",
                data=pdf_file,
                file_name="AI_Forensics_Report.pdf",
                mime="application/pdf"
            )

    except Exception as error:
        st.error("PDF generation failed.")
        st.exception(error)
