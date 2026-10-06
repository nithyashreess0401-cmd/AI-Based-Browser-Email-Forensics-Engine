import os
import base64

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


# Always use the folder where this Python file is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CREDENTIALS_FILE = os.path.join(
    BASE_DIR,
    "credentials.json"
)

TOKEN_FILE = os.path.join(
    BASE_DIR,
    "token.json"
)


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

        token.write(
            creds.to_json()
        )

    print("Gmail login saved to token.json")


# Connect to Gmail
service = build(
    "gmail",
    "v1",
    credentials=creds
)

print("\n===== GMAIL CONNECTION SUCCESSFUL =====")


# ==========================================================
# SEARCH EMAILS
# ==========================================================

email_address = input(
    "Enter sender email address: "
).strip()

start_date = input(
    "Enter start date (YYYY-MM-DD): "
).strip()

end_date = input(
    "Enter end date (YYYY-MM-DD): "
).strip()


# Convert YYYY-MM-DD to Gmail's date format
gmail_start_date = start_date.replace(
    "-",
    "/"
)

gmail_end_date = end_date.replace(
    "-",
    "/"
)


# Gmail search query
query = (
    f"from:{email_address} "
    f"after:{gmail_start_date} "
    f"before:{gmail_end_date}"
)


print("\nSearching Gmail...")
print("Search:", query)


results = service.users().messages().list(
    userId="me",
    q=query,
    maxResults=20
).execute()


messages = results.get(
    "messages",
    []
)


print(
    "Number of emails found:",
    len(messages)
)


# Stop safely if no emails were found
if not messages:

    print(
        "No matching emails found."
    )

    exit()


print(
    "\n===== GMAIL EMAILS =====\n"
)


# ==========================================================
# DISPLAY MATCHING EMAILS
# ==========================================================

for i, message in enumerate(
    messages,
    start=1
):

    email_data = service.users().messages().get(
        userId="me",
        id=message["id"],
        format="metadata",
        metadataHeaders=[
            "From",
            "To",
            "Subject",
            "Date"
        ]
    ).execute()


    headers = email_data[
        "payload"
    ][
        "headers"
    ]


    print(
        f"Email {i}"
    )


    for header in headers:

        print(
            f"{header['name']}: "
            f"{header['value']}"
        )


    print(
        "----------------------------"
    )


# ==========================================================
# SELECT EMAIL FOR FORENSIC ANALYSIS
# ==========================================================

while True:

    try:
        choice = int(
            input(
                "\nEnter the Email number you want to analyze: "
            )
        )

        if 1 <= choice <= len(messages):
            break

        print(
            f"Please enter a number between 1 and {len(messages)}."
        )

    except ValueError:
        print("Please enter a valid number.")


# Get the selected email ID
message_id = messages[choice - 1]["id"]


raw_message = service.users().messages().get(
    userId="me",
    id=message_id,
    format="raw"
).execute()


# Decode the Gmail message
email_bytes = base64.urlsafe_b64decode(
    raw_message["raw"] + "=="
)


# ==========================================================
# SAVE EMAIL AS .EML
# ==========================================================

email_file = os.path.join(
    BASE_DIR,
    "emails",
    "gmail_message.eml"
)


# Make sure the emails folder exists
os.makedirs(
    os.path.dirname(email_file),
    exist_ok=True
)


with open(
    email_file,
    "wb"
) as file:

    file.write(
        email_bytes
    )


print(
    "\n===== EMAIL SAVED ====="
)

print(
    "Saved to:",
    email_file
)
