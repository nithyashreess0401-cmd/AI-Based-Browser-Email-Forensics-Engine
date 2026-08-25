import email
from email import policy

# Open the email
with open("emails/sample.eml", "rb") as file:
    msg = email.message_from_binary_file(file, policy=policy.default)

# Save metadata
with open("output/metadata.txt", "w") as file:
    file.write("===== EMAIL METADATA =====\n\n")

    file.write(f"From: {msg['From']}\n")
    file.write(f"To: {msg['To']}\n")
    file.write(f"Reply-To: {msg['Reply-To']}\n")
    file.write(f"Subject: {msg['Subject']}\n")
    file.write(f"Date: {msg['Date']}\n")
    file.write(f"Message-ID: {msg['Message-ID']}\n")
    file.write(f"Content-Type: {msg['Content-Type']}\n")

print("Metadata saved successfully!")