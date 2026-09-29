import os
import email
from email import policy


# ==========================================================
# PROJECT PATH
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


# ==========================================================
# EMAIL FILE PATH
# ==========================================================

EMAIL_FILE = os.path.join(
    BASE_DIR,
    "emails",
    "gmail_message.eml"
)


# ==========================================================
# OUTPUT DIRECTORY
# ==========================================================

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "output"
)

# Create output folder automatically
os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


# ==========================================================
# OUTPUT FILE
# ==========================================================

OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "metadata.txt"
)


# ==========================================================
# CHECK EMAIL FILE
# ==========================================================

if not os.path.exists(EMAIL_FILE):

    print("ERROR: Email file not found!")

    print(
        f"Expected file:\n{EMAIL_FILE}"
    )

    raise FileNotFoundError(
        EMAIL_FILE
    )


# ==========================================================
# OPEN EMAIL
# ==========================================================

with open(
    EMAIL_FILE,
    "rb"
) as file:

    msg = email.message_from_binary_file(
        file,
        policy=policy.default
    )


# ==========================================================
# SAVE EMAIL METADATA
# ==========================================================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "===== EMAIL METADATA =====\n\n"
    )

    file.write(
        f"From: {msg.get('From', 'N/A')}\n"
    )

    file.write(
        f"To: {msg.get('To', 'N/A')}\n"
    )

    file.write(
        f"Reply-To: {msg.get('Reply-To', 'N/A')}\n"
    )

    file.write(
        f"Subject: {msg.get('Subject', 'N/A')}\n"
    )

    file.write(
        f"Date: {msg.get('Date', 'N/A')}\n"
    )

    file.write(
        f"Message-ID: {msg.get('Message-ID', 'N/A')}\n"
    )

    file.write(
        f"Content-Type: {msg.get('Content-Type', 'N/A')}\n"
    )


# ==========================================================
# FINISH
# ==========================================================

print(
    "Metadata saved successfully!"
)

print(
    f"Saved to: {OUTPUT_FILE}"
)