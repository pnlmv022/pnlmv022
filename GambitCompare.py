import csv
import glob
import io
import os
import re
import subprocess
import sys
from datetime import datetime

import pandas as pd
import requests

# ==============================
# CONFIG
# ==============================

INC_PATH = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\Gambit_General\Gambit_General_Data\incident.csv"
ALERT_PATH = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\GambitCompare\GambitCompare_Alerts\alert-report*.csv"
LOOKUP_PATH = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\GambitCompare\GambitCompare_HCC\*.csv"
KEY_FILE = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\Gambit_General\Gambit_General_Key\Oauth2ClientCredentialsToken.txt"
ALL_STORES_PATH = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\Gambit_General\Gambit_General_Data\ALL_Stores.csv"

RUN_DATE_FILE = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\Gambit_General\Gambit_General_Data\OverviewRunDate.csv"
GET_ALL_STORES_SCRIPT = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\Gambit_General\Gambit_General_Scripts\GetAllStores.py"
GET_ALL_STORES_NAME = "GetAllStores.py"
GET_ALL_STORES_MAX_AGE_DAYS = 5
GET_ALL_STORES_TIMEOUT = 1800  # seconds

RUN_TS_FILE = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = rf"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\GambitCompare\GambitCompare_MismatchAlerts\mismatch_alerts_{RUN_TS_FILE}.csv"

ALERT_FOLDER = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\GambitCompare\GambitCompare_Alerts"
ERROR_FOLDER = r"C:\Users\pnlmv022\OneDrive - AholdDelhaize.com\Gambit\GambitCompare\GambitGambit_Error"
ERROR_FILE = os.path.join(ERROR_FOLDER, "error.log")

REQUEST_TIMEOUT = 20
VERIFY_SSL = True
MAX_LOG_TEXT = 1000

ALLOWED_ALERT_CODES = {
    "missing in action",
    "excessive restarts",
    "no hdmi connections",
    "incorrect screen resolution",
}

# Brand → report endpoint mapping
BRAND_REPORT_URLS = {
    "albertheijn": "https://gambit-dmi-media-devices-albertheijn-prd.kaas.prd.k8s.ah.technology/v1/alerts/report",
    "etos":        "https://gambit-dmi-media-devices-etos-prd.kaas.prd.k8s.ah.technology/v1/alerts/report",
    "gall":        "https://gambit-dmi-media-devices-gall-prd.kaas.prd.k8s.ah.technology/v1/alerts/report",
}

# Label (as used in ALL_Stores.csv / mismatch export) → store-detail endpoint mapping
STORE_DETAIL_URLS = {
    "AH": "https://gambit-dmi-media-devices-albertheijn-prd.kaas.prd.k8s.ah.technology/v1/stores/",
    "ET": "https://gambit-dmi-media-devices-etos-prd.kaas.prd.k8s.ah.technology/v1/stores/",
    "GG": "https://gambit-dmi-media-devices-gall-prd.kaas.prd.k8s.ah.technology/v1/stores/",
}

# ==============================
# SETUP
# ==============================

os.makedirs(ALERT_FOLDER, exist_ok=True)
os.makedirs(ERROR_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

with open(ERROR_FILE, "w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["label", "store_id", "mac-address", "hostname", "message"])

# ==============================
# LOGGING
# ==============================

def log_error(msg: str):
    """Write a system-level error row with empty device fields."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["", "", "", "", f"{timestamp} - {msg}"])
    with open(ERROR_FILE, "a", encoding="utf-8", newline="") as f:
        f.write(buf.getvalue())

def log_error_row(label: str = "", store_id: str = "", mac_address: str = "", hostname: str = "", msg: str = ""):
    """Write a structured device-level error row to the CSV error file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([label, store_id, mac_address, hostname, f"{timestamp} - {msg}"])
    with open(ERROR_FILE, "a", encoding="utf-8", newline="") as f:
        f.write(buf.getvalue())

def shorten_text(value, limit=MAX_LOG_TEXT):
    if value is None:
        return ""
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"

# ==============================
# CLEAN / NORMALIZE HELPERS
# ==============================

def clean(x):
    if pd.isna(x):
        return ""
    return str(x).replace("\xa0", " ").strip()

def clean_mac(x):
    value = clean(x).lower()
    value = value.replace("-", ":").replace(".", ":")
    value = re.sub(r":{2,}", ":", value)
    return value.strip(":")

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [
        re.sub(r"\s+", "_", str(c).replace("\xa0", " ").strip())
        for c in df.columns
    ]
    return df

def extract_digits(value):
    if pd.isna(value):
        return ""
    m = re.search(r"(\d+)", str(value))
    return m.group(1) if m else ""

def extract_first4_digits(value):
    if pd.isna(value):
        return ""
    text = str(value).strip()
    m = re.search(r"(\d{4})", text)
    return m.group(1) if m else text[:4].strip()

def normalize_hostname(value):
    if pd.isna(value):
        return ""
    text = str(value).strip().lower()
    m = re.search(r"(gambit-(\d+))", text)
    if not m:
        return text
    number = int(m.group(2))
    return f"gambit-{number:02d}"

def build_incident_key(location_num, hostname):
    return f"{clean(location_num)}{clean(hostname)}"

# ==============================
# BRAND / API BASE / LABEL
# ==============================

def resolve_brand_from_alert_file(alert_file_path: str) -> str:
    filename = os.path.basename(alert_file_path).lower()

    if filename.startswith("alert-report-albertheijn-"):
        return "albertheijn"
    if filename.startswith("alert-report-etos-"):
        return "etos"
    if filename.startswith("alert-report-gall-"):
        return "gall"

    raise ValueError(
        f"Unknown alert file prefix for '{filename}'. "
        "Expected one of: alert-report-albertheijn-, "
        "alert-report-etos-, alert-report-gall-"
    )

def resolve_api_base_from_brand(brand: str) -> str:
    mapping = {
        "albertheijn": "https://gambit-dmi-media-devices-albertheijn-prd.kaas.prd.k8s.ah.technology/v1/alerts/",
        "etos":        "https://gambit-dmi-media-devices-etos-prd.kaas.prd.k8s.ah.technology/v1/alerts/",
        "gall":        "https://gambit-dmi-media-devices-gall-prd.kaas.prd.k8s.ah.technology/v1/alerts/",
    }
    if brand not in mapping:
        raise ValueError(f"Unknown brand: {brand}")
    return mapping[brand]

def resolve_label_from_brand(brand: str) -> str:
    mapping = {
        "albertheijn": "AH",
        "etos":        "ET",
        "gall":        "GG",
    }
    if brand not in mapping:
        raise ValueError(f"Unknown brand for label: {brand}")
    return mapping[brand]

def normalize_api_base(url: str) -> str:
    return url if url.endswith("/") else url + "/"

# ==============================
# API HELPERS
# ==============================

def build_headers(token: str):
    return {
        "accept": "application/json",
        "X-Authorization": token,
        "Content-Type": "application/json",
    }

def try_get_alert(url: str, headers: dict):
    try:
        return requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            verify=VERIFY_SSL
        )
    except requests.RequestException as e:
        log_error(f"GET error for {url}: {e}")
        return None
    except Exception as e:
        log_error(f"Unexpected GET error for {url}: {e}")
        return None

def try_put_alert(url: str, headers: dict, payload: dict):
    try:
        return requests.put(
            url,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            verify=VERIFY_SSL
        )
    except requests.RequestException as e:
        log_error(f"PUT error for {url}: {e}")
        return None
    except Exception as e:
        log_error(f"Unexpected PUT error for {url}: {e}")
        return None

def update_alert_notes(alert_id: str, notes: str, headers: dict, api_base: str):
    base = normalize_api_base(api_base)
    payload = {"notes": notes}

    candidates = [
        f"{base}{alert_id}",
        f"{base}{alert_id}/",
        f"{base}{alert_id}/notes",
        f"{base}{alert_id}/note",
    ]

    last_status = None
    last_text   = ""
    last_url    = None

    for url in candidates:
        g = try_get_alert(url, headers)
        if g is not None:
            print(f"GET  {url} -> {g.status_code}")
            if g.status_code >= 400:
                log_error(f"GET failed for {url}: {g.status_code} - {shorten_text(g.text)}")

        r = try_put_alert(url, headers, payload)
        if r is None:
            continue

        print(f"PUT  {url} -> {r.status_code}")
        print(f"PUT response body: {shorten_text(r.text, 500)}")

        last_status = r.status_code
        last_text   = r.text
        last_url    = url

        if r.status_code in (200, 201, 202, 204):
            return True, r.status_code, url, r.text

    return False, last_status, last_url, last_text

# ==============================
# FILE HELPERS
# ==============================

def get_latest_file(pattern: str, description: str) -> str:
    files = glob.glob(pattern)
    if not files:
        raise FileNotFoundError(f"No {description} files found with pattern: {pattern}")
    return max(files, key=os.path.getctime)

def safe_read_csv(path: str, **kwargs) -> pd.DataFrame:
    """
    Read a CSV using common encodings used by UTF-8 and Windows exports.

    UTF-8 is attempted first. Windows-1252 handles characters such as the
    non-breaking space represented by byte 0xA0.
    """
    requested_encoding = kwargs.pop("encoding", None)

    encodings = (
        [requested_encoding]
        if requested_encoding
        else ["utf-8-sig", "cp1252", "latin-1"]
    )

    decoding_errors = []

    for encoding in encodings:
        try:
            dataframe = pd.read_csv(
                path,
                dtype=str,
                encoding=encoding,
                **kwargs,
            )

            if encoding not in ("utf-8", "utf-8-sig"):
                message = (
                    f"CSV '{path}' was read using fallback encoding "
                    f"'{encoding}'."
                )
                print(f"⚠ {message}")
                log_error(message)

            return dataframe

        except UnicodeDecodeError as e:
            decoding_errors.append(f"{encoding}: {e}")
            continue

        except Exception as e:
            raise Exception(
                f"Failed to read CSV '{path}' using encoding "
                f"'{encoding}': {e}"
            ) from e

    raise Exception(
        f"Failed to decode CSV '{path}'. Encodings attempted: "
        f"{', '.join(encodings)}. Errors: {' | '.join(decoding_errors)}"
    )

def require_columns(df: pd.DataFrame, required_cols: list, file_label: str):
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise Exception(f"Missing required columns in {file_label}: {missing}")

# ==============================
# NOTES COLUMN NORMALIZATION
# ==============================

def normalize_notes_column(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensure a single canonical 'Notes' column exists on df.

    Alert reports can contain a 'Notes' column with capital N. If a stray
    lowercase 'notes' column is also present, merge its values into 'Notes'
    (preferring any existing 'Notes' value) and drop the duplicate so we
    never end up with a blank 'Notes' plus a populated lowercase 'notes'.
    """
    df = df.copy()
    has_upper = "Notes" in df.columns
    has_lower = "notes" in df.columns

    if has_upper and has_lower:
        upper_is_blank = df["Notes"].isna() | (df["Notes"].astype(str).str.strip() == "")
        df.loc[upper_is_blank, "Notes"] = df.loc[upper_is_blank, "notes"]
        df = df.drop(columns=["notes"])
    elif has_lower and not has_upper:
        df = df.rename(columns={"notes": "Notes"})
    elif not has_upper and not has_lower:
        df["Notes"] = ""

    df["Notes"] = df["Notes"].fillna("")
    return df

# ==============================
# STORE HOURS / CLOSED-STORE DETECTION
# ==============================

def load_all_stores_map(path: str) -> dict:
    """
    Load ALL_Stores.csv and build a mapping of (label, store_number) -> internal
    store id, used to call the brand store-detail API.
    """
    mapping = {}

    if not os.path.exists(path):
        log_error(f"ALL_Stores file not found: {path}")
        return mapping

    try:
        df = safe_read_csv(path, sep=None, engine="python")
    except Exception as e:
        log_error(f"Failed to read ALL_Stores file '{path}': {e}")
        return mapping

    df = normalize_columns(df)

    id_col = next((c for c in df.columns if c.lower() == "id"), None)
    store_col = next(
        (c for c in df.columns if c.lower() in
            ["storeid", "store_id", "store_number", "storenumber", "store"]),
        None
    )
    label_col = next(
        (c for c in df.columns if c.lower() in ["label", "brand"]),
        None
    )

    if not id_col or not store_col or not label_col:
        log_error(f"ALL_Stores file missing required columns. Found: {df.columns.tolist()}")
        return mapping

    for _, row in df.iterrows():
        store_number = extract_digits(row.get(store_col, ""))
        label = clean(row.get(label_col, "")).upper()
        internal_id = clean(row.get(id_col, ""))
        if store_number and label and internal_id:
            mapping[(label, store_number)] = internal_id

    print(f"✅ ALL_Stores entries loaded: {len(mapping)}")
    return mapping


def fetch_store_detail(label: str, internal_id: str, token: str):
    """GET the store detail JSON from the brand-specific store endpoint."""
    base = STORE_DETAIL_URLS.get(label)
    if not base or not internal_id:
        return None

    url = f"{base}{internal_id}"
    fetch_headers = {
        "accept": "application/json",
        "X-Authorization": token,
    }

    try:
        response = requests.get(url, headers=fetch_headers, timeout=REQUEST_TIMEOUT, verify=VERIFY_SSL)
    except requests.RequestException as e:
        log_error(f"GET store detail error for {url}: {e}")
        return None
    except Exception as e:
        log_error(f"Unexpected GET store detail error for {url}: {e}")
        return None

    if response.status_code != 200:
        log_error(f"Store detail fetch failed for {url}: {response.status_code} - {shorten_text(response.text)}")
        return None

    try:
        return response.json()
    except Exception as e:
        log_error(f"Failed to parse store detail JSON from {url}: {e}")
        return None


def parse_play_hours_entries(store_detail: dict) -> list:
    """
    Extract (date, openTime, closeTime) tuples from effectivePlayHours, sorted
    by date. playStartTime/playEndTime/playHoursOverrides are intentionally
    ignored, as closure must be determined only from effectivePlayHours.
    """
    entries = []
    play_hours = store_detail.get("effectivePlayHours") if store_detail else None
    if not isinstance(play_hours, list):
        return entries

    for entry in play_hours:
        if not isinstance(entry, dict):
            continue

        date_str   = entry.get("date") or entry.get("effectiveDate") or entry.get("day")
        open_time  = entry.get("openTime")
        close_time = entry.get("closeTime")

        if not date_str or open_time is None or close_time is None:
            continue

        # Dates may arrive as a plain "YYYY-MM-DD" or as an ISO timestamp
        # ("YYYY-MM-DDTHH:MM:SS[Z]"); only the date portion is relevant here.
        raw_date = str(date_str).strip()
        date_part = raw_date.split("T", 1)[0].split(" ", 1)[0]

        parsed_date = None
        for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d", "%d/%m/%Y"):
            try:
                parsed_date = datetime.strptime(date_part, fmt).date()
                break
            except ValueError:
                continue

        if parsed_date is None:
            continue

        entries.append((parsed_date, str(open_time).strip(), str(close_time).strip()))

    entries.sort(key=lambda e: e[0])
    return entries


def compute_store_status(store_detail: dict, as_of=None):
    """
    Determine ('Open' | 'Closed' | 'Unknown', note) for a store, based solely on
    effectivePlayHours[].openTime / closeTime.

    A store is closed for a date when openTime equals closeTime (including
    "00:00" to "00:00"). If a future effectivePlayHours entry has different
    open/close times, the note includes the next opening date/time.
    """
    as_of = as_of or datetime.now().date()
    entries = parse_play_hours_entries(store_detail)

    # Per spec, closure is determined only from today's effectivePlayHours
    # entry. If the API did not return an entry dated today (e.g. the store
    # or the list itself is missing/stale), we deliberately report "Unknown"
    # rather than inferring from other dates, since no other field is
    # authoritative for "is the store open right now".
    today_entry = next((e for e in entries if e[0] == as_of), None)
    if today_entry is None:
        return "Unknown", ""

    _, open_time, close_time = today_entry
    if open_time != close_time:
        return "Open", ""

    future_entry = next(
        (e for e in entries if e[0] > as_of and e[1] != e[2]),
        None
    )

    if future_entry:
        future_date, future_open, _ = future_entry
        note = f"Store is closed - opening at {future_date.strftime('%d-%m-%Y')} {future_open}"
    else:
        note = "Store is closed"

    return "Closed", note


def resolve_store_status_and_note(label: str, store_number: str, stores_map: dict, token: str, status_cache: dict):
    """
    Resolve a mismatch row's store status/note using the ALL_Stores.csv mapping
    plus the brand store-detail API. Results are cached per (label, store_number)
    to avoid repeat API calls for the same store within a run.
    """
    cache_key = (label, store_number)
    if cache_key in status_cache:
        return status_cache[cache_key]

    internal_id = stores_map.get(cache_key)
    if not internal_id:
        result = ("Unknown", "")
        status_cache[cache_key] = result
        return result

    store_detail = fetch_store_detail(label, internal_id, token)
    if store_detail is None:
        result = ("Unknown", "")
        status_cache[cache_key] = result
        return result

    result = compute_store_status(store_detail)
    status_cache[cache_key] = result
    return result

# ==============================
# RUN-DATE CHECK / GETALLSTORES
# ==============================

def read_run_dates(path: str) -> list:
    """Read OverviewRunDate.csv (name;run_date) into a list of [name, run_date] rows."""
    if not os.path.exists(path):
        log_error(f"Run date file not found: {path}")
        return []
    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f, delimiter=";")
        header = next(reader, None)
        for row in reader:
            if len(row) >= 2 and row[0].strip():
                rows.append([row[0].strip(), row[1].strip()])
    return rows


def write_run_dates(path: str, rows: list):
    """Write rows back atomically (temp file + replace) to avoid corrupting the CSV."""
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["name", "run_date"])
        writer.writerows(rows)
    os.replace(tmp_path, path)


def update_run_date(path: str, name: str, date_str: str):
    rows = read_run_dates(path)
    for row in rows:
        if row[0].lower() == name.lower():
            row[1] = date_str
            break
    else:
        rows.append([name, date_str])
    write_run_dates(path, rows)


def check_and_run_get_all_stores():
    """Run GetAllStores.py if its run_date is older than the max age (or missing/invalid)."""
    rows  = read_run_dates(RUN_DATE_FILE)
    entry = next((r for r in rows if r[0].lower() == GET_ALL_STORES_NAME.lower()), None)

    needs_run = True
    if entry:
        try:
            last_run = datetime.strptime(entry[1], "%Y%m%d")
            age_days = (datetime.now() - last_run).days
            print(f"{GET_ALL_STORES_NAME} last run: {entry[1]} ({age_days} day(s) ago)")
            needs_run = age_days > GET_ALL_STORES_MAX_AGE_DAYS
        except ValueError:
            log_error(f"Invalid run_date '{entry[1]}' for {GET_ALL_STORES_NAME} in {RUN_DATE_FILE}")
            print(f"⚠ Invalid run_date '{entry[1]}', script will be run")
    else:
        print(f"⚠ No entry for {GET_ALL_STORES_NAME} in run date file, script will be run")

    if not needs_run:
        print(f"✅ {GET_ALL_STORES_NAME} is up to date, skipping")
        return

    if not os.path.exists(GET_ALL_STORES_SCRIPT):
        msg = f"Script not found: {GET_ALL_STORES_SCRIPT}"
        print(f"❌ {msg}")
        log_error(msg)
        return

    print(f"▶ Running {GET_ALL_STORES_SCRIPT} ...")
    try:
        result = subprocess.run(
            [sys.executable, GET_ALL_STORES_SCRIPT],
            cwd=os.path.dirname(GET_ALL_STORES_SCRIPT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=GET_ALL_STORES_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        msg = f"{GET_ALL_STORES_NAME} timed out after {GET_ALL_STORES_TIMEOUT}s"
        print(f"❌ {msg}")
        log_error(msg)
        return
    except Exception as e:
        msg = f"Exception running {GET_ALL_STORES_NAME}: {e}"
        print(f"❌ {msg}")
        log_error(msg)
        return

    if result.returncode != 0:
        msg = (f"{GET_ALL_STORES_NAME} failed: exit={result.returncode}, "
               f"stderr={shorten_text(result.stderr)}")
        print(f"❌ {msg}")
        log_error(msg)
        return  # do NOT update the date on failure

    print(f"✅ {GET_ALL_STORES_NAME} finished successfully")
    try:
        today = datetime.now().strftime("%Y%m%d")
        update_run_date(RUN_DATE_FILE, GET_ALL_STORES_NAME, today)
        print(f"✅ Updated run_date for {GET_ALL_STORES_NAME} → {today}")
    except Exception as e:
        msg = f"Could not update run date file: {e}"
        print(f"❌ {msg}")
        log_error(msg)


# ==============================
# LOAD TOKEN
# ==============================

if not os.path.exists(KEY_FILE):
    raise FileNotFoundError(f"Key file not found: {KEY_FILE}")

with open(KEY_FILE, "r", encoding="utf-8") as f:
    AUTH_TOKEN = f.read().strip()

if not AUTH_TOKEN:
    raise Exception("Auth token is empty. Check Key.txt.")

headers = build_headers(AUTH_TOKEN)

# ==============================
# CHECK & RUN GETALLSTORES
# ==============================

print("\n" + "=" * 80)
print(f"STEP: Checking run date for {GET_ALL_STORES_NAME}")
print("=" * 80)
check_and_run_get_all_stores()

# ==============================
# FETCH FRESH ALERT REPORTS
# ==============================

def clear_alert_folder(folder: str):
    """Remove all files in the alerts folder, keeping the folder itself."""
    removed = 0
    errors  = 0
    for filename in os.listdir(folder):
        filepath = os.path.join(folder, filename)
        if os.path.isfile(filepath):
            try:
                os.remove(filepath)
                removed += 1
            except Exception as e:
                log_error(f"Could not remove alert file '{filepath}': {e}")
                print(f"⚠ Could not remove '{filepath}': {e}")
                errors += 1
    print(f"🗑  Cleared alert folder: {removed} file(s) removed, {errors} error(s).")


def fetch_alert_reports(brand_urls: dict, token: str, dest_folder: str, run_ts: str):
    """
    For each brand, GET /v1/alerts/report (accepts text/csv) and save to
    dest_folder as alert-report-<brand>-<timestamp>.csv
    Returns the list of file paths that were successfully written.
    """
    saved_files = []

    for brand, url in brand_urls.items():
        print(f"\nFetching alert report for brand '{brand}' from {url} ...")

        fetch_headers = {
            "accept": "text/csv",
            "X-Authorization": token,
        }

        try:
            response = requests.get(
                url,
                headers=fetch_headers,
                timeout=120,
                verify=VERIFY_SSL,
            )
        except requests.RequestException as e:
            msg = f"Network error fetching report for brand '{brand}': {e}"
            print(f"❌ {msg}")
            log_error(msg)
            continue
        except Exception as e:
            msg = f"Unexpected error fetching report for brand '{brand}': {e}"
            print(f"❌ {msg}")
            log_error(msg)
            continue

        if response.status_code != 200:
            msg = (
                f"Report fetch for brand '{brand}' returned HTTP {response.status_code}. "
                f"Body: {shorten_text(response.text)}"
            )
            print(f"❌ {msg}")
            log_error(msg)
            continue

        content = response.text
        if not content.strip():
            msg = f"Report for brand '{brand}' is empty."
            print(f"⚠ {msg}")
            log_error(msg)
            continue

        dest_filename = f"alert-report-{brand}-{run_ts}.csv"
        dest_path     = os.path.join(dest_folder, dest_filename)

        try:
            with open(dest_path, "w", encoding="utf-8", newline="") as f:
                f.write(content)
            print(f"✅ Saved alert report → {dest_path}")
            saved_files.append(dest_path)
        except Exception as e:
            msg = f"Could not write report file for brand '{brand}': {e}"
            print(f"❌ {msg}")
            log_error(msg)

    return saved_files


print("\n" + "=" * 80)
print("STEP: Refreshing alert files from API")
print("=" * 80)

clear_alert_folder(ALERT_FOLDER)
fetched_files = fetch_alert_reports(BRAND_REPORT_URLS, AUTH_TOKEN, ALERT_FOLDER, RUN_TS_FILE)

if not fetched_files:
    raise RuntimeError(
        "No alert report files could be fetched from the API. "
        "Check your token, network connectivity, and error.log."
    )

print(f"\n✅ Fetched {len(fetched_files)} alert report file(s).")

# ==============================
# LOAD FILES
# ==============================

incident_file = get_latest_file(INC_PATH, "incident")
lookup_file   = get_latest_file(LOOKUP_PATH, "lookup")
alert_files   = glob.glob(ALERT_PATH)

if not alert_files:
    raise FileNotFoundError(f"No alert files found with pattern: {ALERT_PATH}")

print("Using incident file:")
print(incident_file)
print("Lookup file:")
print(lookup_file)

print("\nAlert files to process:")
for af in sorted(alert_files, key=os.path.getctime):
    print(af)

inc       = safe_read_csv(incident_file)
lookup_df = safe_read_csv(lookup_file, sep=";")

# ==============================
# LOOKUP PREP
# ==============================

lookup_df = normalize_columns(lookup_df)

mac_col = next((c for c in lookup_df.columns if "mac" in c.lower()), None)
host_col = next(
    (c for c in lookup_df.columns if c.lower() in ["hcc-id", "hcc_id", "hostname", "host_name"]),
    None
)

if mac_col is None or host_col is None:
    raise Exception(f"Lookup columns not found: {lookup_df.columns.tolist()}")

print(f"✅ MAC column: {mac_col}")
print(f"✅ Hostname column: {host_col}")

lookup_df[mac_col]  = lookup_df[mac_col].apply(clean_mac)
lookup_df[host_col] = lookup_df[host_col].apply(normalize_hostname)

mac_lookup = {
    clean_mac(mac): normalize_hostname(host)
    for mac, host in zip(lookup_df[mac_col], lookup_df[host_col])
    if clean_mac(mac)
}

print(f"✅ Lookup entries: {len(mac_lookup)}")

# ==============================
# RESOLVE HOSTNAME
# ==============================

def resolve_hostname(row, label: str = ""):
    mac      = clean_mac(row.get("Mac_Address", row.get("Mac Address", row.get("mac_address", ""))))
    host     = normalize_hostname(row.get("Host_Name", row.get("Host Name", row.get("host_name", ""))))
    # Derive store_id from Location_Info the same way the main loop does,
    # so it is available before alerts["location"] column is built.
    store_id = extract_first4_digits(row.get("Location_Info", ""))

    if mac.startswith("00:01:80"):
        return host

    if mac and mac in mac_lookup:
        return mac_lookup[mac]

    if mac:
        log_error_row(
            label=label,
            store_id=store_id,
            mac_address=mac,
            hostname=host,
            msg=f"MAC not found in lookup: {mac}",
        )
    return host

# ==============================
# PREPARE INCIDENTS
# ==============================

inc = normalize_columns(inc)
inc.columns = [c.lower() for c in inc.columns]

require_columns(inc, ["location", "short_description"], "incident file")

inc["location_num"] = inc["location"].apply(extract_digits)
inc["hostname"]     = inc["short_description"].apply(normalize_hostname)
inc["key"]          = inc.apply(
    lambda row: build_incident_key(row.get("location_num", ""), row.get("hostname", "")),
    axis=1
)

inc = inc[inc["key"].astype(str).str.strip() != ""].copy()

if "sys_created_on" in inc.columns:
    inc = inc.sort_values("sys_created_on", ascending=False)

inc_unique       = inc.drop_duplicates(subset="key", keep="first")
incident_lookup  = inc_unique.set_index("key").to_dict(orient="index")
incident_keys    = set(incident_lookup.keys())

print(f"✅ Unique incident keys: {len(incident_lookup)}")

# ==============================
# ALL_STORES MAP (for closed-store check)
# ==============================

all_stores_map     = load_all_stores_map(ALL_STORES_PATH)
store_status_cache = {}

# ==============================
# PROCESS ALERT FILES
# ==============================

all_mismatches = []

total_success             = 0
total_fail                = 0
total_matches             = 0
total_mismatches          = 0
total_closed_notes_written = 0

for alert_file in sorted(alert_files, key=os.path.getctime):
    print("\n" + "=" * 80)
    print(f"Processing alert file: {alert_file}")

    try:
        brand    = resolve_brand_from_alert_file(alert_file)
        api_base = resolve_api_base_from_brand(brand)
        label    = resolve_label_from_brand(brand)
    except Exception as e:
        log_error(f"Brand/API/label resolve failed for {alert_file}: {e}")
        print(f"❌ Skipping file, cannot resolve brand/api/label: {e}")
        continue

    print(f"Brand: {brand} | Label: {label}")
    print(f"Resolved API base: {api_base}")

    try:
        alerts = safe_read_csv(alert_file)
    except Exception as e:
        log_error(str(e))
        print(f"❌ Failed to read alert file: {e}")
        continue

    alerts = normalize_columns(alerts)
    alerts = normalize_notes_column(alerts)

    required_alert_cols = ["Status", "Alert_Code", "Location_Info", "Host_Name", "Alert_ID"]
    missing_alert_cols  = [c for c in required_alert_cols if c not in alerts.columns]
    if missing_alert_cols:
        log_error(f"Missing required alert columns in {alert_file}: {missing_alert_cols}")
        print(f"❌ Missing required alert columns in {alert_file}: {missing_alert_cols}")
        continue

    alerts = alerts[
        (alerts["Status"].astype(str).str.lower() == "open")
        & (alerts["Alert_Code"].astype(str).str.lower().isin(ALLOWED_ALERT_CODES))
    ].copy()

    if alerts.empty:
        print("ℹ No relevant open alerts in file")
        continue

    # Pass label into resolve_hostname so MAC-not-found rows are logged with correct label
    alerts["Resolved_Hostname"] = alerts.apply(lambda row: resolve_hostname(row, label), axis=1)
    alerts["Host_Name"]         = alerts["Resolved_Hostname"]
    alerts["location"]          = alerts["Location_Info"].apply(extract_first4_digits)
    alerts["store"]             = alerts["Location_Info"].apply(extract_digits)
    alerts["Host_Name"]         = alerts["Host_Name"].apply(normalize_hostname)
    alerts["key"]               = alerts.apply(
        lambda row: build_incident_key(row.get("location", ""), row.get("Host_Name", "")),
        axis=1
    )

    mismatch = alerts[~alerts["key"].isin(incident_keys)].copy()
    matches  = alerts[ alerts["key"].isin(incident_keys)].copy()

    file_matches    = len(matches)
    file_mismatches = len(mismatch)

    total_matches    += file_matches
    total_mismatches += file_mismatches

    print(f"Matches: {file_matches}")
    print(f"Mismatches: {file_mismatches}")

    if file_mismatches > 0:
        mismatch.insert(0, "Label", label)
        mismatch = normalize_notes_column(mismatch)

        if "Store_Status" not in mismatch.columns:
            mismatch["Store_Status"] = "Unknown"

        file_closed_notes_written = 0

        for idx in mismatch.index:
            # "location" is the first-4-digits store number derived from
            # Location_Info a few lines above (alerts["location"] = ...),
            # carried over into `mismatch` since it is a .copy() of `alerts`.
            # Fall back to recomputing it from Location_Info directly in case
            # that column is ever renamed/removed upstream.
            if "location" in mismatch.columns:
                store_number = str(mismatch.at[idx, "location"]).strip()
            elif "Location_Info" in mismatch.columns:
                store_number = extract_first4_digits(mismatch.at[idx, "Location_Info"])
            else:
                store_number = ""

            status, note = resolve_store_status_and_note(
                label, store_number, all_stores_map, AUTH_TOKEN, store_status_cache
            )
            mismatch.at[idx, "Store_Status"] = status

            if status == "Closed" and note:
                mismatch.at[idx, "Notes"] = note
                file_closed_notes_written += 1

                alert_id   = str(mismatch.at[idx, "Alert_ID"]).strip() if "Alert_ID" in mismatch.columns else ""
                alert_mac  = clean_mac(mismatch.at[idx, "Mac_Address"]) if "Mac_Address" in mismatch.columns else ""
                alert_host = str(mismatch.at[idx, "Host_Name"]).strip() if "Host_Name" in mismatch.columns else ""

                if not alert_id:
                    log_error_row(
                        label=label,
                        store_id=store_number,
                        mac_address=alert_mac,
                        hostname=alert_host,
                        msg="Missing Alert_ID for closed-store mismatch row, cannot update notes via API",
                    )
                    continue

                try:
                    ok, status_code, final_url, response_text = update_alert_notes(
                        alert_id=alert_id,
                        notes=note,
                        headers=headers,
                        api_base=api_base
                    )
                    if ok:
                        print(f"✅ Closed-store alert {alert_id} notes updated ({status_code}) via {final_url}")
                    else:
                        print(f"❌ Closed-store alert {alert_id} notes update failed ({status_code}) via {final_url}")
                        log_error_row(
                            label=label,
                            store_id=store_number,
                            mac_address=alert_mac,
                            hostname=alert_host,
                            msg=(
                                f"Closed-store alert {alert_id} notes update failed. "
                                f"status={status_code}, url={final_url}, response={shorten_text(response_text)}"
                            ),
                        )
                except Exception as e:
                    print(f"❌ Closed-store alert {alert_id} notes update exception: {e}")
                    log_error_row(
                        label=label,
                        store_id=store_number,
                        mac_address=alert_mac,
                        hostname=alert_host,
                        msg=f"Closed-store alert {alert_id} notes update exception: {e}",
                    )

        if file_closed_notes_written:
            print(f"📝 Closed-store notes written for this file: {file_closed_notes_written}")
        total_closed_notes_written += file_closed_notes_written

        all_mismatches.append(mismatch)

    print("Updating alerts via API...")
    file_success = 0
    file_fail    = 0

    for _, alert in matches.iterrows():
        alert_id = str(alert.get("Alert_ID", "")).strip()
        key      = str(alert.get("key",      "")).strip()

        # Use "location" (first 4 digits of Location_Info) as store_id
        alert_store = str(alert.get("location",  "")).strip()
        alert_mac   = clean_mac(alert.get("Mac_Address", ""))
        alert_host  = str(alert.get("Host_Name", "")).strip()

        if not alert_id:
            file_fail  += 1
            total_fail += 1
            log_error_row(
                label=label,
                store_id=alert_store,
                mac_address=alert_mac,
                hostname=alert_host,
                msg=f"Missing Alert_ID for key={key} in file={alert_file}",
            )
            print(f"❌ Missing Alert_ID for key={key}")
            continue

        incident = incident_lookup.get(key)
        if not incident:
            file_fail  += 1
            total_fail += 1
            log_error_row(
                label=label,
                store_id=alert_store,
                mac_address=alert_mac,
                hostname=alert_host,
                msg=f"Incident lookup missing for matched key={key} in file={alert_file}",
            )
            print(f"❌ Incident lookup missing for key={key}")
            continue

        notes = (
            f"{incident.get('number', '')} - "
            f"{incident.get('sys_created_on', '')} - "
            f"{incident.get('assignment_group', '')} - "
            f"{incident.get('state', '')}"
        ).strip()

        try:
            ok, status_code, final_url, response_text = update_alert_notes(
                alert_id=alert_id,
                notes=notes,
                headers=headers,
                api_base=api_base
            )

            if ok:
                file_success  += 1
                total_success += 1
                print(f"✅ Alert {alert_id} updated ({status_code}) via {final_url}")
            else:
                file_fail  += 1
                total_fail += 1
                print(f"❌ Alert {alert_id} failed ({status_code}) via {final_url}")
                log_error_row(
                    label=label,
                    store_id=alert_store,
                    mac_address=alert_mac,
                    hostname=alert_host,
                    msg=(
                        f"Alert {alert_id} update failed. "
                        f"file={alert_file}, status={status_code}, url={final_url}, "
                        f"response={shorten_text(response_text)}"
                    ),
                )
        except Exception as e:
            file_fail  += 1
            total_fail += 1
            print(f"❌ Alert {alert_id} exception: {e}")
            log_error_row(
                label=label,
                store_id=alert_store,
                mac_address=alert_mac,
                hostname=alert_host,
                msg=f"Alert {alert_id} unexpected exception: {e}",
            )

    print(f"File API success: {file_success}")
    print(f"File API failed:  {file_fail}")

# ==============================
# EXPORT COMBINED MISMATCH
# ==============================

try:
    if all_mismatches:
        combined_mismatch = pd.concat(all_mismatches, ignore_index=True)
    else:
        combined_mismatch = pd.DataFrame(columns=["Label", "Notes", "Store_Status"])

    combined_mismatch = normalize_notes_column(combined_mismatch)
    if "Store_Status" not in combined_mismatch.columns:
        combined_mismatch["Store_Status"] = "Unknown"

    closed_mask        = combined_mismatch["Store_Status"] == "Closed"
    closed_count       = int(closed_mask.sum())
    closed_with_notes  = int((closed_mask & (combined_mismatch["Notes"].astype(str).str.strip() != "")).sum())

    print(f"📝 Closed-store notes written into mismatch export: {total_closed_notes_written}")
    print(f"📝 Closed rows with non-empty Notes: {closed_with_notes}/{closed_count}")
    if closed_count and closed_with_notes != closed_count:
        log_error(
            f"{closed_count - closed_with_notes} closed-store mismatch row(s) are missing Notes in the export."
        )

    combined_mismatch.to_csv(OUTPUT_FILE, index=False, encoding="utf-8")
    print(f"\n✅ Combined mismatch exported to: {OUTPUT_FILE}")
except Exception as e:
    log_error(f"Failed to export mismatch file: {e}")
    raise

# ==============================
# FINAL
# ==============================

print("\n✅ DONE")
print(f"✅ Total matches:    {total_matches}")
print(f"⚠ Total mismatches: {total_mismatches}")
print(f"✅ API success:      {total_success}")
print(f"⚠ API failed:       {total_fail}")

try:
    error_df = pd.read_csv(ERROR_FILE, dtype=str)
    device_rows = error_df[
        error_df[["label", "store_id", "mac-address", "hostname"]]
        .apply(lambda r: any(str(v).strip() for v in r), axis=1)
    ]
    system_rows = error_df[
        ~error_df[["label", "store_id", "mac-address", "hostname"]]
        .apply(lambda r: any(str(v).strip() for v in r), axis=1)
    ]
    total_error_rows = len(error_df)
    if total_error_rows == 0:
        print("✅ No errors logged")
    else:
        print(f"⚠ Error rows logged: {total_error_rows} total "
              f"({len(device_rows)} device-level, {len(system_rows)} system-level)")
        print(f"⚠ See log: {ERROR_FILE}")
except Exception as e:
    print(f"⚠ Could not inspect error log: {e}")
