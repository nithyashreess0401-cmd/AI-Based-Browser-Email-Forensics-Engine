import os
import sqlite3
import shutil
import json
import pandas as pd


USER = os.environ["USERPROFILE"]

all_history = []
all_bookmarks = []
all_downloads = []


# --------------------------------------------------
# CHROMIUM HISTORY
# --------------------------------------------------

def extract_chromium_history(browser, history_path):

    if not os.path.exists(history_path):
        return

    temp = f"temp_{browser}_history"

    try:
        shutil.copy2(history_path, temp)

        conn = sqlite3.connect(temp)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                urls.url,
                urls.title,
                datetime(
                    visits.visit_time / 1000000 - 11644473600,
                    'unixepoch'
                )
            FROM urls
            JOIN visits ON urls.id = visits.url
            ORDER BY visits.visit_time DESC
        """)

        for url, title, visit_time in cursor.fetchall():

            all_history.append({
                "Browser": browser,
                "URL": url,
                "Title": title,
                "Visit Time": visit_time
            })

        # Downloads
        try:
            cursor.execute("""
                SELECT
                    downloads.tab_url,
                    downloads.target_path,
                    datetime(
                        downloads.start_time / 1000000 - 11644473600,
                        'unixepoch'
                    )
                FROM downloads
            """)

            for url, path, download_time in cursor.fetchall():

                all_downloads.append({
                    "Browser": browser,
                    "URL": url,
                    "File": path,
                    "Download Time": download_time
                })

        except Exception:
            pass

        conn.close()
        os.remove(temp)

        print(
            f"{browser}: "
            f"{len([x for x in all_history if x['Browser'] == browser])} "
            "history records found"
        )

    except Exception as e:

        print(f"{browser} history error: {e}")

        if os.path.exists(temp):
            os.remove(temp)


# --------------------------------------------------
# CHROMIUM BOOKMARKS
# --------------------------------------------------

def extract_chromium_bookmarks(browser, bookmark_path):

    if not os.path.exists(bookmark_path):
        return

    try:

        with open(
            bookmark_path,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        def scan(node):

            if isinstance(node, dict):

                if node.get("type") == "url":

                    all_bookmarks.append({
                        "Browser": browser,
                        "Bookmark Name": node.get("name"),
                        "URL": node.get("url")
                    })

                for value in node.values():
                    scan(value)

            elif isinstance(node, list):

                for item in node:
                    scan(item)

        scan(data)

        print(
            f"{browser}: "
            f"{len([x for x in all_bookmarks if x['Browser'] == browser])} "
            "bookmarks found"
        )

    except Exception as e:

        print(f"{browser} bookmark error: {e}")


# --------------------------------------------------
# FIREFOX HISTORY
# --------------------------------------------------

def extract_firefox(profile_path):

    places = os.path.join(
        profile_path,
        "places.sqlite"
    )

    if not os.path.exists(places):
        return

    temp = "temp_firefox_places.sqlite"

    try:

        shutil.copy2(places, temp)

        conn = sqlite3.connect(temp)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                url,
                title,
                datetime(
                    last_visit_date / 1000000,
                    'unixepoch'
                )
            FROM moz_places
            WHERE last_visit_date IS NOT NULL
            ORDER BY last_visit_date DESC
        """)

        for url, title, visit_time in cursor.fetchall():

            all_history.append({
                "Browser": "Firefox",
                "URL": url,
                "Title": title,
                "Visit Time": visit_time
            })

        conn.close()
        os.remove(temp)

        print("Firefox history extracted")

    except Exception as e:

        print(f"Firefox error: {e}")

        if os.path.exists(temp):
            os.remove(temp)


# --------------------------------------------------
# FIND ALL BROWSER PROFILES
# --------------------------------------------------

def scan_browsers():

    local = os.path.join(
        USER,
        "AppData",
        "Local"
    )

    roaming = os.path.join(
        USER,
        "AppData",
        "Roaming"
    )

    chromium_browsers = {

        "Chrome": os.path.join(
            local,
            "Google",
            "Chrome",
            "User Data"
        ),

        "Edge": os.path.join(
            local,
            "Microsoft",
            "Edge",
            "User Data"
        ),

        "Brave": os.path.join(
            local,
            "BraveSoftware",
            "Brave-Browser",
            "User Data"
        ),

        "Opera": os.path.join(
            roaming,
            "Opera Software",
            "Opera Stable"
        )
    }

    # Chrome / Edge / Brave / Opera
    for browser, user_data in chromium_browsers.items():

        if not os.path.exists(user_data):
            continue

        print(f"\nChecking {browser}...")

        try:

            for profile in os.listdir(user_data):

                profile_path = os.path.join(
                    user_data,
                    profile
                )

                if not os.path.isdir(profile_path):
                    continue

                history = os.path.join(
                    profile_path,
                    "History"
                )

                bookmarks = os.path.join(
                    profile_path,
                    "Bookmarks"
                )

                if os.path.exists(history):

                    extract_chromium_history(
                        browser,
                        history
                    )

                if os.path.exists(bookmarks):

                    extract_chromium_bookmarks(
                        browser,
                        bookmarks
                    )

        except Exception as e:

            print(f"{browser} error: {e}")

    # Firefox
    firefox_root = os.path.join(
        roaming,
        "Mozilla",
        "Firefox",
        "Profiles"
    )

    if os.path.exists(firefox_root):

        print("\nChecking Firefox...")

        for profile in os.listdir(firefox_root):

            profile_path = os.path.join(
                firefox_root,
                profile
            )

            if os.path.isdir(profile_path):

                extract_firefox(
                    profile_path
                )


# --------------------------------------------------
# SAVE RESULTS
# --------------------------------------------------

def save_results():

    if all_history:

        history_df = pd.DataFrame(
            all_history
        )

        history_df.to_csv(
            "history.csv",
            index=False
        )

        print(
            f"\nHistory saved: "
            f"{len(history_df)} records"
        )

    else:

        print("\nNo browser history found.")

    if all_bookmarks:

        bookmarks_df = pd.DataFrame(
            all_bookmarks
        )

        bookmarks_df.to_csv(
            "bookmarks.csv",
            index=False
        )

        print(
            f"Bookmarks saved: "
            f"{len(bookmarks_df)} records"
        )

    else:

        print("No bookmarks found.")

    if all_downloads:

        downloads_df = pd.DataFrame(
            all_downloads
        )

        downloads_df.to_csv(
            "downloads.csv",
            index=False
        )

        print(
            f"Downloads saved: "
            f"{len(downloads_df)} records"
        )

    else:

        print("No downloads found.")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == "__main__":

    print("\n======================================")
    print("     MULTI-BROWSER FORENSICS")
    print("======================================")

    scan_browsers()

    save_results()

    print("\nBrowser forensic extraction completed!")