import email
from email import policy

# Open the email file
with open("emails/sample.eml", "rb") as file:
    msg = email.message_from_binary_file(file, policy=policy.default)

# Print basic information
print("From:", msg["From"])
print("To:", msg["To"])
print("Subject:", msg["Subject"])
print("Date:", msg["Date"])

print("\n----------------------------")
print("EMAIL BODY")
print("----------------------------")

# Read the email body
if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            print(part.get_content())
else:
    print(msg.get_content())