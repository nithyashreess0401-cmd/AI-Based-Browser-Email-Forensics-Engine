import email
from email import policy

# Open the email
with open("emails/sample.eml", "rb") as file:
    msg = email.message_from_binary_file(file, policy=policy.default)

print("===== EMAIL HEADER ANALYSIS =====\n")

print("From        :", msg["From"])
print("To          :", msg["To"])
print("Reply-To    :", msg["Reply-To"])
print("Subject     :", msg["Subject"])
print("Date        :", msg["Date"])
print("Message-ID  :", msg["Message-ID"])
print("Content-Type:", msg["Content-Type"])