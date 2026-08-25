import email
from email import policy
import re

# Open the email
with open("emails/sample.eml", "rb") as file:
    msg = email.message_from_binary_file(file, policy=policy.default)

# Read the email body
if msg.is_multipart():
    body = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body += part.get_content()
else:
    body = msg.get_content()

# Extract URLs
urls = re.findall(r'https?://[^\s]+', body)

print("===== URLS FOUND =====\n")

with open("output/urls.txt", "w") as file:
    if urls:
        for url in urls:
            print(url)
            file.write(url + "\n")
    else:
        print("No URLs found.")
        file.write("No URLs found.")