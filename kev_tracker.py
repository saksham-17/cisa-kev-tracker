import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
STATE_FILE = DATA_DIR / "kev_state.json"


def fetch_catalog():
    """Download and validate the latest CISA KEV catalog."""
    request = urllib.request.Request(
        FEED_URL,
        headers={"User-Agent": "kev-tracker/1.0"}
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        catalog = json.load(response)

    vulnerabilities = catalog.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise ValueError("Invalid catalog: vulnerabilities list missing")

    # Avoid treating a malformed or empty response as a clean update.
    if not vulnerabilities:
        raise ValueError("Catalog is unexpectedly empty")

    for item in vulnerabilities:
        if not isinstance(item, dict) or not item.get("cveID"):
            raise ValueError("Catalog contains an invalid CVE entry")

    return catalog


def load_state():
    """Load CVE IDs seen during the previous successful run."""
    if not STATE_FILE.exists():
        return None

    with STATE_FILE.open("r", encoding="utf-8") as file:
        state = json.load(file)

    if not isinstance(state.get("cve_ids"), list):
        raise ValueError("Invalid state file: cve_ids missing")

    return set(state["cve_ids"])


def save_json(path, data):
    """Write JSON through a temporary file to avoid partial writes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")

    with temporary_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")

    temporary_path.replace(path)


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Fetch first. If this fails, don't change the existing baseline.
    catalog = fetch_catalog()
    previous_ids = load_state()

    vulnerabilities = catalog["vulnerabilities"]

    # Use CVE IDs as stable identifiers.
    current_by_id = {
        item["cveID"]: item for item in vulnerabilities
    }
    current_ids = set(current_by_id)

    # First run establishes a baseline rather than reporting
    # the entire historical catalog as newly discovered.
    is_first_run = previous_ids is None

    if is_first_run:
        new_entries = []
    else:
        new_entries = [
            current_by_id[cve_id]
            for cve_id in current_ids - previous_ids
        ]

    new_entries.sort(
        key=lambda item: (item.get("dateAdded", ""), item["cveID"]),
        reverse=True
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": FEED_URL,
        "catalog_version": catalog.get("catalogVersion"),
        "catalog_release_date": catalog.get("dateReleased"),
        "total_catalog_entries": len(current_ids),
        "new_entries_count": len(new_entries),
        "first_run": is_first_run,
        "new_entries": [
            {
                "cve_id": item["cveID"],
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "vulnerability_name": item.get("vulnerabilityName", ""),
                "date_added": item.get("dateAdded", ""),
                "description": item.get("shortDescription", ""),
                "required_action": item.get("requiredAction", ""),
                "due_date": item.get("dueDate", ""),
                "ransomware_use": item.get(
                    "knownRansomwareCampaignUse", "Unknown"
                ),
                "notes": item.get("notes", ""),
                "cwes": item.get("cwes", [])
            }
            for item in new_entries
        ]
    }

    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report_file = REPORT_DIR / f"kev_report_{report_date}.json"

    # Save the report before advancing the baseline.
    save_json(report_file, report)
    save_json(REPORT_DIR / "latest.json", report)

    # Store the complete current ID set for the next comparison.
    save_json(
        STATE_FILE,
        {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "catalog_version": catalog.get("catalogVersion"),
            "cve_ids": sorted(current_ids)
        }
    )

    print("\n=== CISA KEV Weekly Tracker ===")
    print(f"Catalog version : {catalog.get('catalogVersion')}")
    print(f"Total CVEs      : {len(current_ids)}")
    print(f"New CVEs        : {len(new_entries)}")
    print(f"First run       : {is_first_run}")
    print(f"Report saved    : {report_file}")

    if is_first_run:
        print("\nBaseline created. Run again after a catalog update "
              "to detect newly added CVEs.")
    elif new_entries:
        print("\nNew vulnerabilities:")
        for item in new_entries:
            print(
                f"- {item['cveID']} | "
                f"{item.get('vendorProject', 'Unknown')} | "
                f"{item.get('product', 'Unknown')} | "
                f"Added: {item.get('dateAdded', 'Unknown')}"
            )
    else:
        print("\nNo new CVE IDs since the previous run.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nERROR: {error}")
        raise SystemExit(1)
