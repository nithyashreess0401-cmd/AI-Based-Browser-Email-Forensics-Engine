```python
import os
import base64
from datetime import datetime, timedelta
from email import message_from_bytes
from email.policy import default

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CREDENTIALS_FILE = os.path.join(BASE_DIR, "credentials.json")
TOKEN_FILE = os.path.join(BASE_DIR, "token.json")
EMAIL_DIR = os.path.join(BASE_DIR, "emails")
EMAIL_FILE = os.path.join(EMAIL_DIR, "gmail_message.eml")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


# --------------------------------------------------
# CONNECT TO GMAIL
# --------------------------------------------------

def connect_to_gmail():
    """Authenticate and return the Gmail API service."""

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
                raise FileNotFoundError(
                    f"Missing credentials file: {CREDENTIALS_FILE}"
                )

            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, "w", encoding="utf-8") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


# --------------------------------------------------
# SEARCH EMAILS
# --------------------------------------------------

def search_emails(service, sender_email, start_date, end_date):
    """
    Search emails from a sender between inclusive dates.

    Dates must use YYYY-MM-DD.
    """

    sender_email = sender_email.strip()

    if not sender_email or "@" not in sender_email:
        raise ValueError("Enter a valid sender email address.")

    start = datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.strptime(end_date, "%Y-%m-%d").date()

    if start > end:
        raise ValueError("Start date must be before or equal to end date.")

    # Gmail after/before boundaries are exclusive.
    after_date = start - timedelta(days=1)
    before_date = end + timedelta(days=1)

    query = (
        f"from:{sender_email} "
        f"after:{after_date.strftime('%Y/%m/%d')} "
        f"before:{before_date.strftime('%Y/%m/%d')}"
    )

    response = service.users().messages().list(
        userId="me",
        q=query,
        maxResults=100
    ).execute()

    messages = response.get("messages", [])

    # Fetch further pages if Gmail returns more than one page.
    while response.get("nextPageToken"):
        response = service.users().messages().list(
            userId="me",
            q=query,
            maxResults=100,
            pageToken=response["nextPageToken"]
        ).execute()

        messages.extend(response.get("messages", []))

    return messages


# --------------------------------------------------
# GET EMAIL DETAILS
# --------------------------------------------------

def get_email_details(service, message_id):
    """Retrieve email headers and the raw email message."""

    result = service.users().messages().get(
        userId="me",
        id=message_id,
        format="raw"
    ).execute()

    raw_data = base64.urlsafe_b64decode(result["raw"])
    email_message = message_from_bytes(
        raw_data, policy=default
    )

    details = {
        "id": message_id,
        "From": email_message.get("From", "Not found"),
        "To": email_message.get("To", "Not found"),
        "Subject": email_message.get("Subject", "(No Subject)"),
        "Date": email_message.get("Date", "Not found"),
        "Message-ID": email_message.get("Message-ID", "Not found"),
    }

    return details, raw_data


# --------------------------------------------------
# SAVE SELECTED EMAIL
# --------------------------------------------------

def save_email(raw_data):
    """Save the selected email in EML format for forensic analysis."""

    os.makedirs(EMAIL_DIR, exist_ok=True)

    with open(EMAIL_FILE, "wb") as email_file:
        email_file.write(raw_data)

    print(f"\nSelected email saved to: {EMAIL_FILE}")


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():
    try:
        service = connect_to_gmail()

        print("\n========== GMAIL EMAIL FORENSICS ==========")

        sender_email = input(
            "Enter sender email address: "
        ).strip()

        start_date = input(
            "Enter start date (YYYY-MM-DD): "
        ).strip()

        end_date = input(
            "Enter end date (YYYY-MM-DD): "
        ).strip()

        messages = search_emails(
            service,
            sender_email,
            start_date,
            end_date
        )

        if not messages:
            print("\nNo matching emails found.")
            return

        print(f"\nFound {len(messages)} matching email(s):\n")

        email_options = []

        for index, message in enumerate(messages, start=1):
            details, raw_data = get_email_details(
                service, message["id"]
            )

            email_options.append((details, raw_data))

            print(f"Email {index}")
            print(f"From: {details['From']}")
            print(f"To: {details['To']}")
            print(f"Subject: {details['Subject']}")
            print(f"Date: {details['Date']}")
            print("-" * 50)

        while True:
            try:
                choice = int(input(
                    "\nEnter the email number to analyze: "
                ))

                if 1 <= choice <= len(email_options):
                    break

                print(
                    f"Enter a number between 1 and {len(email_options)}."
                )

            except ValueError:
                print("Please enter a valid number.")

        selected_details, selected_raw_data = email_options[
            choice - 1
        ]

        save_email(selected_raw_data)

        print("\nSelected email:")
        for key, value in selected_details.items():
            print(f"{key}: {value}")

        print(
            "\nNow run 'python main.py' to generate the forensic report."
        )

    except ValueError as error:
        print(f"\nInput error: {error}")

    except Exception as error:
        print(f"\nGmail operation failed: {error}")


if __name__ == "__main__":
    main()
