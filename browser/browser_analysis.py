import os
import json
import pandas as pd

# Path to Chrome Bookmarks file
bookmark_path = os.path.join(
    os.environ["USERPROFILE"],
    "AppData",
    "Local",
    "Google",
    "Chrome",
    "User Data",
    "Profile 1",
    "Bookmarks"
)

# Read bookmarks file
with open(bookmark_path, "r", encoding="utf-8") as file:
    data = json.load(file)

bookmarks = []

# Function to extract bookmarks
def extract_bookmarks(children):
    for item in children:
        if item["type"] == "url":
            bookmarks.append([item["name"], item["url"]])
        elif item["type"] == "folder":
            extract_bookmarks(item["children"])

# Extract from bookmark bar
extract_bookmarks(data["roots"]["bookmark_bar"]["children"])

# Create DataFrame
df = pd.DataFrame(bookmarks, columns=["Bookmark Name", "URL"])

print(df)

# Save to CSV
df.to_csv("bookmarks.csv", index=False)

print("Bookmarks saved successfully!")