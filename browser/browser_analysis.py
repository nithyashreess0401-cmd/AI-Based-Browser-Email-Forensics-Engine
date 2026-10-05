import os
import sys
import subprocess
import shutil
from datetime import datetime

import pandas as pd


# ============================================================
# PATHS
# ============================================================

SCRIPT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_DIR = os.path.dirname(
    SCRIPT_DIR
)

# Browser extraction script
BROWSER_HISTORY_FILE = os.path.join(
    SCRIPT_DIR,
    "browser_history.py"
)

# Main history database CSV
HISTORY_FILE = os.path.join(
    SCRIPT_DIR,
    "history.csv"
)

# Phishing analysis script
PHISHING_FILE = os.path.join(
    SCRIPT_DIR,
    "suspicious_urls.py"
)

# Possible phishing result locations
RESULT_FILE_BROWSER = os.path.join(
    SCRIPT_DIR,
    "suspicious_urls_v3.csv"
)

RESULT_FILE_ROOT = os.path.join(
    PROJECT_DIR,
    "suspicious_urls_v3.csv"
)

# Temporary history file
TEMP_HISTORY_FILE = os.path.join(
    SCRIPT_DIR,
    "history_analysis_temp.csv"
)


# ============================================================
# PRINT HELPER
# ============================================================

def log(message):
    print(message, flush=True)


# ============================================================
# FIND PHISHING RESULT
# ============================================================

def find_result_file():

    possible_files = [
        RESULT_FILE_BROWSER,
        RESULT_FILE_ROOT
    ]

    for file_path in possible_files:

        if os.path.isfile(file_path):
            return file_path

    return None


# ============================================================
# REMOVE OLD RESULT
# ============================================================

def remove_old_result():

    for file_path in [
        RESULT_FILE_BROWSER,
        RESULT_FILE_ROOT
    ]:

        try:

            if os.path.exists(file_path):
                os.remove(file_path)

        except Exception as error:

            log(
                f"Could not remove old result "
                f"{file_path}: {error}"
            )


# ============================================================
# RUN PYTHON SCRIPT
# ============================================================

def run_python_script(
    script_path,
    working_directory
):

    if not os.path.isfile(script_path):

        raise FileNotFoundError(
            f"Python script not found: "
            f"{script_path}"
        )

    result = subprocess.run(
        [
            sys.executable,
            "-u",
            script_path
        ],
        cwd=working_directory,
        capture_output=True,
        text=True
    )

    return result


# ============================================================
# RUN BROWSER EXTRACTION
# ============================================================

def run_browser_extraction():

    log("")
    log("=" * 60)
    log("STEP 1 - BROWSER HISTORY EXTRACTION")
    log("=" * 60)

    if not os.path.isfile(
        BROWSER_HISTORY_FILE
    ):

        log(
            "ERROR: browser_history.py was not found."
        )

        log(
            f"Expected location: "
            f"{BROWSER_HISTORY_FILE}"
        )

        return False

    try:

        result = run_python_script(
            BROWSER_HISTORY_FILE,
            SCRIPT_DIR
        )

    except Exception as error:

        log(
            f"ERROR running browser_history.py: "
            f"{error}"
        )

        return False

    if result.stdout:

        log(result.stdout)

    if result.returncode != 0:

        log("")
        log("=" * 60)
        log("BROWSER EXTRACTION FAILED")
        log("=" * 60)

        if result.stderr:
            log(result.stderr)

        return False

    if not os.path.isfile(
        HISTORY_FILE
    ):

        log(
            "ERROR: history.csv was not created."
        )

        log(
            f"Expected location: "
            f"{HISTORY_FILE}"
        )

        return False

    return True


# ============================================================
# READ HISTORY
# ============================================================

def read_history():

    if not os.path.isfile(
        HISTORY_FILE
    ):

        raise FileNotFoundError(
            f"history.csv not found: "
            f"{HISTORY_FILE}"
        )

    try:

        df = pd.read_csv(
            HISTORY_FILE
        )

    except Exception as error:

        raise RuntimeError(
            f"Could not read history.csv: "
            f"{error}"
        )

    if df.empty:

        log(
            "WARNING: history.csv is empty."
        )

        return df

    return df


# ============================================================
# NORMALIZE HISTORY COLUMNS
# ============================================================

def normalize_history_columns(df):

    df = df.copy()

    # --------------------------------------------------------
    # URL COLUMN
    # --------------------------------------------------------

    if "URL" not in df.columns:

        possible_url_columns = [
            "url",
            "Url",
            "URL",
            "Link",
            "link"
        ]

        found = None

        for column in possible_url_columns:

            if column in df.columns:

                found = column
                break

        if found:

            df["URL"] = df[found]

        else:

            df["URL"] = ""

    # --------------------------------------------------------
    # BROWSER COLUMN
    # --------------------------------------------------------

    if "Browser" not in df.columns:

        df["Browser"] = "Unknown"

    # --------------------------------------------------------
    # VISIT TIME COLUMN
    # --------------------------------------------------------

    if "Visit Time" not in df.columns:

        possible_time_columns = [
            "visit_time",
            "VisitTime",
            "Timestamp",
            "timestamp",
            "Time",
            "time",
            "Date",
            "date"
        ]

        found = None

        for column in possible_time_columns:

            if column in df.columns:

                found = column
                break

        if found:

            df["Visit Time"] = df[found]

        else:

            df["Visit Time"] = ""

    return df


# ============================================================
# CONVERT VISIT TIME
# ============================================================

def convert_visit_time(df):

    df = df.copy()

    # Keep original value temporarily
    df["_Original Visit Time"] = (
        df["Visit Time"]
    )

    df["Visit Time"] = pd.to_datetime(
        df["Visit Time"],
        errors="coerce"
    )

    return df


# ============================================================
# SHOW HISTORY INFORMATION
# ============================================================

def show_history_information(df):

    log("")
    log("=" * 60)
    log("HISTORY INFORMATION")
    log("=" * 60)

    log(
        f"Total history records: {len(df)}"
    )

    if df.empty:
        return

    log(
        f"Columns: {list(df.columns)}"
    )

    valid_dates = df[
        "Visit Time"
    ].dropna()

    if not valid_dates.empty:

        log(
            f"Earliest visit: "
            f"{valid_dates.min()}"
        )

        log(
            f"Latest visit: "
            f"{valid_dates.max()}"
        )

    log("")
    log("Records by browser:")

    try:

        browser_counts = (
            df["Browser"]
            .astype(str)
            .value_counts()
        )

        for browser, count in (
            browser_counts.items()
        ):

            log(
                f"  {browser}: {count}"
            )

    except Exception:
        pass


# ============================================================
# GET DATE RANGE
#
# The Streamlit app can provide dates through:
#
# INVESTIGATION_START_DATE
# INVESTIGATION_END_DATE
#
# If not provided, ALL available browser history
# is analyzed.
# ============================================================

def get_date_range():

    start_text = os.environ.get(
        "INVESTIGATION_START_DATE",
        ""
    ).strip()

    end_text = os.environ.get(
        "INVESTIGATION_END_DATE",
        ""
    ).strip()

    start_date = None
    end_date = None

    if start_text:

        try:

            start_date = datetime.strptime(
                start_text,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            log(
                "WARNING: Invalid "
                "INVESTIGATION_START_DATE."
            )

    if end_text:

        try:

            end_date = datetime.strptime(
                end_text,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            log(
                "WARNING: Invalid "
                "INVESTIGATION_END_DATE."
            )

    return start_date, end_date


# ============================================================
# FILTER HISTORY
# ============================================================

def filter_history(
    df,
    start_date=None,
    end_date=None
):

    if df.empty:

        return df.copy()

    filtered = df.copy()

    # --------------------------------------------------------
    # If no dates are provided:
    # analyze ALL available data.
    # --------------------------------------------------------

    if (
        start_date is None
        and end_date is None
    ):

        log(
            "Date range: ALL AVAILABLE DATA"
        )

        return filtered

    # --------------------------------------------------------
    # Start date
    # --------------------------------------------------------

    if start_date is not None:

        start_datetime = pd.Timestamp(
            start_date
        )

    else:

        start_datetime = (
            filtered["Visit Time"].min()
        )

    # --------------------------------------------------------
    # End date
    #
    # Add one day so the complete end date
    # is included.
    # --------------------------------------------------------

    if end_date is not None:

        end_datetime = (
            pd.Timestamp(end_date)
            + pd.Timedelta(days=1)
            - pd.Timedelta(microseconds=1)
        )

    else:

        end_datetime = (
            filtered["Visit Time"].max()
        )

    # --------------------------------------------------------
    # Filter
    # --------------------------------------------------------

    filtered = filtered[
        (
            filtered["Visit Time"]
            >= start_datetime
        )
        &
        (
            filtered["Visit Time"]
            <= end_datetime
        )
    ].copy()

    log(
        f"Date range: "
        f"{start_date} -> {end_date}"
    )

    return filtered


# ============================================================
# SAVE TEMPORARY HISTORY FOR AI ANALYSIS
# ============================================================

def save_analysis_history(
    filtered_df
):

    if filtered_df.empty:

        return False

    # Make a copy
    output_df = filtered_df.copy()

    # Restore the original text representation
    if "_Original Visit Time" in output_df.columns:

        output_df["Visit Time"] = (
            output_df[
                "_Original Visit Time"
            ]
        )

        output_df = output_df.drop(
            columns=[
                "_Original Visit Time"
            ]
        )

    output_df.to_csv(
        TEMP_HISTORY_FILE,
        index=False
    )

    return True


# ============================================================
# BACKUP ORIGINAL HISTORY
# ============================================================

def backup_original_history():

    backup_file = os.path.join(
        SCRIPT_DIR,
        "history_original_backup.csv"
    )

    shutil.copy2(
        HISTORY_FILE,
        backup_file
    )

    return backup_file


# ============================================================
# RESTORE ORIGINAL HISTORY
# ============================================================

def restore_original_history(
    backup_file
):

    if not backup_file:
        return

    try:

        if os.path.isfile(
            backup_file
        ):

            shutil.copy2(
                backup_file,
                HISTORY_FILE
            )

            os.remove(
                backup_file
            )

    except Exception as error:

        log(
            f"WARNING: Could not restore "
            f"original history.csv: {error}"
        )


# ============================================================
# RUN PHISHING ANALYSIS
# ============================================================

def run_phishing_analysis():

    log("")
    log("=" * 60)
    log("STEP 2 - AI PHISHING ANALYSIS")
    log("=" * 60)

    if not os.path.isfile(
        PHISHING_FILE
    ):

        log(
            "ERROR: suspicious_urls.py "
            "was not found."
        )

        log(
            f"Expected location: "
            f"{PHISHING_FILE}"
        )

        return False

    try:

        result = run_python_script(
            PHISHING_FILE,
            SCRIPT_DIR
        )

    except Exception as error:

        log(
            f"ERROR running suspicious_urls.py: "
            f"{error}"
        )

        return False

    if result.stdout:

        log(result.stdout)

    if result.returncode != 0:

        log("")
        log("=" * 60)
        log("AI PHISHING ANALYSIS FAILED")
        log("=" * 60)

        if result.stderr:

            log(result.stderr)

        return False

    return True


# ============================================================
# VALIDATE RESULT
# ============================================================

def validate_result():

    result_file = find_result_file()

    if not result_file:

        log("")
        log(
            "ERROR: suspicious_urls_v3.csv "
            "was not generated."
        )

        log(
            "Expected one of:"
        )

        log(
            f"  {RESULT_FILE_BROWSER}"
        )

        log(
            f"  {RESULT_FILE_ROOT}"
        )

        return None

    try:

        result_df = pd.read_csv(
            result_file
        )

    except Exception as error:

        log(
            f"ERROR reading AI result: "
            f"{error}"
        )

        return None

    # --------------------------------------------------------
    # Normalize Status
    # --------------------------------------------------------

    if "Status" not in result_df.columns:

        possible_columns = [
            "Prediction",
            "Result",
            "Label",
            "Classification"
        ]

        found = None

        for column in possible_columns:

            if column in result_df.columns:

                found = column
                break

        if found:

            result_df["Status"] = (
                result_df[found]
            )

        else:

            result_df["Status"] = (
                "UNKNOWN"
            )

    result_df["Status"] = (
        result_df["Status"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    result_df["Status"] = (
        result_df["Status"]
        .replace(
            {
                "UNSAFE": "PHISHING",
                "MALICIOUS": "PHISHING",
                "PHISH": "PHISHING",
                "NOT SAFE": "PHISHING",
                "SAFE": "BENIGN",
                "LEGITIMATE": "BENIGN",
                "NORMAL": "BENIGN"
            }
        )
    )

    return result_df


# ============================================================
# PRINT FINAL STATISTICS
# ============================================================

def print_statistics(
    result_df
):

    total = len(
        result_df
    )

    status = (
        result_df["Status"]
        .astype(str)
        .str.upper()
        .str.strip()
    )

    phishing = int(
        (
            status == "PHISHING"
        ).sum()
    )

    benign = int(
        (
            status == "BENIGN"
        ).sum()
    )

    suspicious = int(
        status.isin(
            [
                "SUSPICIOUS",
                "UNKNOWN"
            ]
        ).sum()
    )

    if phishing == 0:

        risk = "LOW"

    elif phishing <= 3:

        risk = "MEDIUM"

    else:

        risk = "HIGH"

    log("")
    log("=" * 60)
    log("AI PHISHING ANALYSIS SUMMARY")
    log("=" * 60)

    log(
        f"Total URLs       : {total}"
    )

    log(
        f"Phishing URLs    : {phishing}"
    )

    log(
        f"Benign URLs      : {benign}"
    )

    log(
        f"Suspicious       : {suspicious}"
    )

    log(
        f"Risk Level       : {risk}"
    )

    log("=" * 60)

    return (
        total,
        phishing,
        benign,
        suspicious,
        risk
    )


# ============================================================
# MAIN
# ============================================================

def main():

    log("")
    log("=" * 60)
    log("        BROWSER FORENSIC ANALYSIS ENGINE")
    log("=" * 60)

    # --------------------------------------------------------
    # STEP 1
    # --------------------------------------------------------

    extraction_success = (
        run_browser_extraction()
    )

    if not extraction_success:

        return 1

    # --------------------------------------------------------
    # STEP 2
    # Read complete history
    # --------------------------------------------------------

    try:

        history_df = read_history()

    except Exception as error:

        log(
            f"ERROR: {error}"
        )

        return 1

    if history_df.empty:

        log("")
        log(
            "No browser history was extracted."
        )

        return 0

    # --------------------------------------------------------
    # STEP 3
    # Normalize
    # --------------------------------------------------------

    history_df = (
        normalize_history_columns(
            history_df
        )
    )

    history_df = (
        convert_visit_time(
            history_df
        )
    )

    # --------------------------------------------------------
    # STEP 4
    # Show information
    # --------------------------------------------------------

    show_history_information(
        history_df
    )

    # --------------------------------------------------------
    # STEP 5
    # Get investigation date range
    # --------------------------------------------------------

    start_date, end_date = (
        get_date_range()
    )

    # --------------------------------------------------------
    # STEP 6
    # Filter
    # --------------------------------------------------------

    filtered_history = (
        filter_history(
            history_df,
            start_date,
            end_date
        )
    )

    log("")
    log(
        f"Records selected for analysis: "
        f"{len(filtered_history)}"
    )

    # --------------------------------------------------------
    # IMPORTANT
    #
    # Do NOT overwrite history.csv permanently.
    # We temporarily replace it while suspicious_urls.py
    # runs, then restore the complete history.
    # --------------------------------------------------------

    if filtered_history.empty:

        log("")
        log("=" * 60)
        log("NO RECORDS FOR SELECTED DATE RANGE")
        log("=" * 60)

        log(
            "Browser extraction succeeded, "
            "but no records matched the selected dates."
        )

        log(
            "Try a wider date range."
        )

        return 0

    # --------------------------------------------------------
    # STEP 7
    # Save selected history
    # --------------------------------------------------------

    try:

        save_analysis_history(
            filtered_history
        )

    except Exception as error:

        log(
            f"ERROR creating temporary history: "
            f"{error}"
        )

        return 1

    # --------------------------------------------------------
    # STEP 8
    # Backup complete history
    # --------------------------------------------------------

    backup_file = None

    try:

        backup_file = (
            backup_original_history()
        )

        # Replace history.csv temporarily
        shutil.copy2(
            TEMP_HISTORY_FILE,
            HISTORY_FILE
        )

        # Remove old result
        remove_old_result()

        # ----------------------------------------------------
        # STEP 9
        # Run phishing model
        # ----------------------------------------------------

        phishing_success = (
            run_phishing_analysis()
        )

        if not phishing_success:

            return 1

        # ----------------------------------------------------
        # STEP 10
        # Check result
        # ----------------------------------------------------

        result_df = (
            validate_result()
        )

        if result_df is None:

            return 1

        # ----------------------------------------------------
        # STEP 11
        # Print statistics
        # ----------------------------------------------------

        print_statistics(
            result_df
        )

        return 0

    finally:

        # ----------------------------------------------------
        # VERY IMPORTANT:
        # Restore complete history.csv
        # ----------------------------------------------------

        restore_original_history(
            backup_file
        )

        # Remove temporary file

        try:

            if os.path.exists(
                TEMP_HISTORY_FILE
            ):

                os.remove(
                    TEMP_HISTORY_FILE
                )

        except Exception:
            pass

        log("")
        log(
            "Complete history.csv restored."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    exit_code = main()

    sys.exit(
        exit_code
    )