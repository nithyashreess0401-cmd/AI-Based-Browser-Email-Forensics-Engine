import os
import sqlite3
import shutil
import json
import pandas as pd
import tempfile


# ============================================================
# GLOBAL DATA
# ============================================================

USER = os.environ.get("USERPROFILE", os.path.expanduser("~"))

all_history = []
all_bookmarks = []
all_downloads = []


# ============================================================
# HELPER
# ============================================================

def safe_remove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


# ============================================================
# CHROMIUM HISTORY
# Chrome / Edge / Brave / Opera
# ============================================================

def extract_chromium_history(browser, history_path, profile_name="Default"):

    if not os.path.isfile(history_path):
        return

    temp_path = None

    try:

        # Create temporary copy because browser may keep
        # the original SQLite database locked.
        temp_file = tempfile.NamedTemporaryFile(
            prefix=f"{browser}_",
            suffix="_History",
            delete=False
        )

        temp_path = temp_file.name
        temp_file.close()

        shutil.copy2(history_path, temp_path)

        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        # ----------------------------------------------------
        # HISTORY
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                urls.url,
                urls.title,
                datetime(
                    visits.visit_time / 1000000 - 11644473600,
                    'unixepoch',
                    'localtime'
                ) AS visit_time
            FROM visits
            INNER JOIN urls
                ON visits.url = urls.id
            WHERE urls.url IS NOT NULL
            ORDER BY visits.visit_time DESC
            """
        )

        rows = cursor.fetchall()

        for url, title, visit_time in rows:

            all_history.append(
                {
                    "Browser": browser,
                    "Profile": profile_name,
                    "URL": url or "",
                    "Title": title or "",
                    "Visit Time": visit_time or ""
                }
            )

        # ----------------------------------------------------
        # DOWNLOADS
        # ----------------------------------------------------

        try:

            cursor.execute(
                """
                SELECT
                    tab_url,
                    target_path,
                    datetime(
                        start_time / 1000000 - 11644473600,
                        'unixepoch',
                        'localtime'
                    ) AS download_time
                FROM downloads
                """
            )

            download_rows = cursor.fetchall()

            for url, path, download_time in download_rows:

                all_downloads.append(
                    {
                        "Browser": browser,
                        "Profile": profile_name,
                        "URL": url or "",
                        "File": path or "",
                        "Download Time": download_time or ""
                    }
                )

        except sqlite3.Error:
            # Some Chromium versions may have a different
            # downloads schema.
            pass

        conn.close()

        print(
            f"{browser} [{profile_name}]: "
            f"{len(rows)} history records found"
        )

    except sqlite3.Error as e:

        print(
            f"{browser} [{profile_name}] SQLite error: {e}"
        )

    except Exception as e:

        print(
            f"{browser} [{profile_name}] history error: {e}"
        )

    finally:

        safe_remove(temp_path)


# ============================================================
# CHROMIUM BOOKMARKS
# ============================================================

def extract_chromium_bookmarks(
    browser,
    bookmark_path,
    profile_name="Default"
):

    if not os.path.isfile(bookmark_path):
        return

    try:

        with open(
            bookmark_path,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        count_before = len(all_bookmarks)

        def scan(node):

            if isinstance(node, dict):

                if node.get("type") == "url":

                    all_bookmarks.append(
                        {
                            "Browser": browser,
                            "Profile": profile_name,
                            "Bookmark Name": node.get(
                                "name",
                                ""
                            ),
                            "URL": node.get(
                                "url",
                                ""
                            )
                        }
                    )

                for value in node.values():
                    scan(value)

            elif isinstance(node, list):

                for item in node:
                    scan(item)

        scan(data)

        count_after = len(all_bookmarks)

        print(
            f"{browser} [{profile_name}]: "
            f"{count_after - count_before} bookmarks found"
        )

    except json.JSONDecodeError as e:

        print(
            f"{browser} [{profile_name}] "
            f"bookmark JSON error: {e}"
        )

    except Exception as e:

        print(
            f"{browser} [{profile_name}] "
            f"bookmark error: {e}"
        )


# ============================================================
# FIREFOX HISTORY
# ============================================================

def extract_firefox_history(
    profile_path,
    profile_name=""
):

    places_path = os.path.join(
        profile_path,
        "places.sqlite"
    )

    if not os.path.isfile(places_path):
        return

    temp_path = None

    try:

        temp_file = tempfile.NamedTemporaryFile(
            prefix="Firefox_",
            suffix="_places.sqlite",
            delete=False
        )

        temp_path = temp_file.name
        temp_file.close()

        shutil.copy2(
            places_path,
            temp_path
        )

        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                p.url,
                p.title,
                datetime(
                    h.visit_date / 1000000,
                    'unixepoch',
                    'localtime'
                ) AS visit_time
            FROM moz_historyvisits h
            INNER JOIN moz_places p
                ON h.place_id = p.id
            WHERE p.url IS NOT NULL
            ORDER BY h.visit_date DESC
            """
        )

        rows = cursor.fetchall()

        for url, title, visit_time in rows:

            all_history.append(
                {
                    "Browser": "Firefox",
                    "Profile": profile_name,
                    "URL": url or "",
                    "Title": title or "",
                    "Visit Time": visit_time or ""
                }
            )

        conn.close()

        print(
            f"Firefox [{profile_name}]: "
            f"{len(rows)} history records found"
        )

    except sqlite3.Error as e:

        print(
            f"Firefox [{profile_name}] SQLite error: {e}"
        )

    except Exception as e:

        print(
            f"Firefox [{profile_name}] history error: {e}"
        )

    finally:

        safe_remove(temp_path)


# ============================================================
# FIND CHROMIUM PROFILES
# ============================================================

def get_chromium_profiles(user_data_path):

    profiles = []

    if not os.path.isdir(user_data_path):
        return profiles

    try:

        for item in os.listdir(user_data_path):

            profile_path = os.path.join(
                user_data_path,
                item
            )

            if not os.path.isdir(profile_path):
                continue

            # Chrome profile folders normally look like:
            #
            # Default
            # Profile 1
            # Profile 2
            # Profile 3
            #
            # Also allow Guest Profile.

            if (
                item == "Default"
                or item.startswith("Profile ")
                or item == "Guest Profile"
            ):

                profiles.append(
                    (
                        item,
                        profile_path
                    )
                )

    except Exception as e:

        print(
            f"Could not scan profiles: {e}"
        )

    return profiles


# ============================================================
# PROCESS CHROMIUM BROWSER
# ============================================================

def process_chromium_browser(
    browser,
    user_data_path
):

    if not os.path.isdir(user_data_path):

        print(
            f"{browser}: not installed"
        )

        return

    print(
        f"\nChecking {browser}..."
    )

    profiles = get_chromium_profiles(
        user_data_path
    )

    if not profiles:

        print(
            f"{browser}: no browser profiles found"
        )

        return

    for profile_name, profile_path in profiles:

        print(
            f"  Checking profile: "
            f"{profile_name}"
        )

        # ----------------------------------------------------
        # HISTORY
        # ----------------------------------------------------

        history_path = os.path.join(
            profile_path,
            "History"
        )

        if os.path.isfile(history_path):

            extract_chromium_history(
                browser,
                history_path,
                profile_name
            )

        else:

            print(
                f"  {browser}: history not found "
                f"for {profile_name}"
            )

        # ----------------------------------------------------
        # BOOKMARKS
        # ----------------------------------------------------

        bookmarks_path = os.path.join(
            profile_path,
            "Bookmarks"
        )

        if os.path.isfile(bookmarks_path):

            extract_chromium_bookmarks(
                browser,
                bookmarks_path,
                profile_name
            )


# ============================================================
# FIREFOX PROFILES
# ============================================================

def process_firefox():

    firefox_root = os.path.join(
        USER,
        "AppData",
        "Roaming",
        "Mozilla",
        "Firefox",
        "Profiles"
    )

    if not os.path.isdir(firefox_root):

        print(
            "\nFirefox: not installed "
            "or profiles not found."
        )

        return

    print(
        "\nChecking Firefox..."
    )

    try:

        for profile_name in os.listdir(
            firefox_root
        ):

            profile_path = os.path.join(
                firefox_root,
                profile_name
            )

            if not os.path.isdir(profile_path):
                continue

            extract_firefox_history(
                profile_path,
                profile_name
            )

    except Exception as e:

        print(
            f"Firefox scanning error: {e}"
        )


# ============================================================
# SCAN ALL BROWSERS
# ============================================================

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

    # --------------------------------------------------------
    # CHROME
    # --------------------------------------------------------

    chrome_path = os.path.join(
        local,
        "Google",
        "Chrome",
        "User Data"
    )

    process_chromium_browser(
        "Chrome",
        chrome_path
    )

    # --------------------------------------------------------
    # EDGE
    # --------------------------------------------------------

    edge_path = os.path.join(
        local,
        "Microsoft",
        "Edge",
        "User Data"
    )

    process_chromium_browser(
        "Edge",
        edge_path
    )

    # --------------------------------------------------------
    # BRAVE
    # --------------------------------------------------------

    brave_path = os.path.join(
        local,
        "BraveSoftware",
        "Brave-Browser",
        "User Data"
    )

    process_chromium_browser(
        "Brave",
        brave_path
    )

    # --------------------------------------------------------
    # OPERA
    # --------------------------------------------------------

    opera_path = os.path.join(
        roaming,
        "Opera Software",
        "Opera Stable"
    )

    process_chromium_browser(
        "Opera",
        opera_path
    )

    # --------------------------------------------------------
    # FIREFOX
    # --------------------------------------------------------

    process_firefox()


# ============================================================
# SAVE HISTORY
# ============================================================

def save_history():

    output_file = os.path.join(
        os.path.dirname(
            os.path.abspath(__file__)
        ),
        "history.csv"
    )

    if not all_history:

        print(
            "\nNo browser history was found."
        )

        # Still create CSV with correct columns.
        empty_df = pd.DataFrame(
            columns=[
                "Browser",
                "Profile",
                "URL",
                "Title",
                "Visit Time"
            ]
        )

        empty_df.to_csv(
            output_file,
            index=False
        )

        return

    df = pd.DataFrame(
        all_history
    )

    # Remove completely empty URLs.
    df = df[
        df["URL"]
        .astype(str)
        .str.strip()
        != ""
    ]

    # Remove duplicate records.
    df = df.drop_duplicates(
        subset=[
            "Browser",
            "Profile",
            "URL",
            "Visit Time"
        ]
    )

    # Sort newest first.
    df["Visit Time"] = pd.to_datetime(
        df["Visit Time"],
        errors="coerce"
    )

    df = df.sort_values(
        "Visit Time",
        ascending=False
    )

    df["Visit Time"] = df[
        "Visit Time"
    ].dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    df.to_csv(
        output_file,
        index=False
    )

    print(
        f"\nHistory saved:"
    )

    print(
        f"  File: {output_file}"
    )

    print(
        f"  Total records: {len(df)}"
    )

    print(
        f"  Browsers: "
        f"{df['Browser'].nunique()}"
    )


# ============================================================
# SAVE BOOKMARKS
# ============================================================

def save_bookmarks():

    output_file = os.path.join(
        os.path.dirname(
            os.path.abspath(__file__)
        ),
        "bookmarks.csv"
    )

    if not all_bookmarks:

        print(
            "\nNo bookmarks found."
        )

        empty_df = pd.DataFrame(
            columns=[
                "Browser",
                "Profile",
                "Bookmark Name",
                "URL"
            ]
        )

        empty_df.to_csv(
            output_file,
            index=False
        )

        return

    df = pd.DataFrame(
        all_bookmarks
    )

    df = df.drop_duplicates()

    df.to_csv(
        output_file,
        index=False
    )

    print(
        f"\nBookmarks saved: "
        f"{len(df)} records"
    )


# ============================================================
# SAVE DOWNLOADS
# ============================================================

def save_downloads():

    output_file = os.path.join(
        os.path.dirname(
            os.path.abspath(__file__)
        ),
        "downloads.csv"
    )

    if not all_downloads:

        print(
            "\nNo downloads found."
        )

        empty_df = pd.DataFrame(
            columns=[
                "Browser",
                "Profile",
                "URL",
                "File",
                "Download Time"
            ]
        )

        empty_df.to_csv(
            output_file,
            index=False
        )

        return

    df = pd.DataFrame(
        all_downloads
    )

    df = df.drop_duplicates()

    df.to_csv(
        output_file,
        index=False
    )

    print(
        f"\nDownloads saved: "
        f"{len(df)} records"
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("             MULTI-BROWSER FORENSICS")
    print("=" * 60)

    scan_browsers()

    save_history()

    save_bookmarks()

    save_downloads()

    print()
    print("=" * 60)
    print("Browser forensic extraction completed!")
    print("=" * 60)

    print(
        f"\nTotal history records : "
        f"{len(all_history)}"
    )

    print(
        f"Total bookmarks       : "
        f"{len(all_bookmarks)}"
    )

    print(
        f"Total downloads       : "
        f"{len(all_downloads)}"
    )