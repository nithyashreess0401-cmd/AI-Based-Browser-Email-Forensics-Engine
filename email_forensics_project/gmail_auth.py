import os
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Always use the folder where this Python file is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CREDENTIALS_FILE = os.path.join(BASE_DIR, "credentials.json")
TOKEN_FILE = os.path.join(BASE_DIR, "token.json")

creds = None

# Check for saved login
if os.path.exists(TOKEN_FILE):
    print("Saved Gmail login found.")
    creds = Credentials.from_authorized_user_file(
        TOKEN_FILE,
        SCOPES
    )

# If there is no valid login, authenticate
if not creds or not creds.valid:

    if creds and creds.expired and creds.refresh_token:
        print("Refreshing Gmail login...")
        creds.refresh(Request())

    else:
        print("Opening Google login...")

        flow = InstalledAppFlow.from_client_secrets_file(
            CREDENTIALS_FILE,
            SCOPES
        )

        creds = flow.run_local_server(
            port=0,
            access_type="offline",
            prompt="consent"
        )

    # Save the authorization
    with open(TOKEN_FILE, "w") as token:
        token.write(creds.to_json())

    print("Gmail login saved to token.json")

# Connect to Gmail
service = build(
    "gmail",
    "v1",
    credentials=creds
)

print("\n===== GMAIL CONNECTION SUCCESSFUL =====")

# Get emails
results = service.users().messages().list(
    userId="me",
    maxResults=5
).execute()

messages = results.get("messages", [])

print("Number of emails found:", len(messages))
print("\n===== GMAIL EMAILS =====\n")

for i, message in enumerate(messages, start=1):

    email_data = service.users().messages().get(
        userId="me",
        id=message["id"],
        format="metadata",
        metadataHeaders=["From", "To", "Subject", "Date"]
    ).execute()

    headers = email_data["payload"]["headers"]

    print(f"Email {i}")

    for header in headers:
        print(f"{header['name']}: {header['value']}")

    print("----------------------------")
    import base64

# Get the first Gmail email
message_id = messages[0]["id"]

raw_message = service.users().messages().get(
    userId="me",
    id=message_id,
    format="raw"
).execute()

# Decode the Gmail message
email_bytes = base64.urlsafe_b64decode(
    raw_message["raw"] + "=="
)

# Save it as an .eml file
email_file = os.path.join(
    BASE_DIR,
    "emails",
    "gmail_message.eml"
)

with open(email_file, "wb") as file:
    file.write(email_bytes)

print("\n===== EMAIL SAVED =====")
print("Saved to:", email_file)