import os
import shutil
import sqlite3
import pandas as pd

history_path = os.path.join(
    os.environ["USERPROFILE"],
    "AppData",
    "Local",
    "Google",
    "Chrome",
    "User Data",
    "Default",
    "History"
)

temp_history = "History_Copy"

shutil.copy2(history_path, temp_history)

conn = sqlite3.connect(temp_history)
cursor = conn.cursor()

cursor.execute("SELECT url, title FROM urls LIMIT 10")

rows = cursor.fetchall()

df = pd.DataFrame(rows, columns=["URL", "Title"])

print(df)

df.to_csv("history.csv", index=False)

print("Browser history saved successfully!")

conn.close()

os.remove(temp_history)