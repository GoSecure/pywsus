#!/usr/bin/env python3
"""check_build.py — Update data/win_builds.json from Microsoft release health pages.

Scrapes the official Microsoft documentation to discover new Windows build
numbers and adds them to the local data/win_builds.json dictionary, organized
by OS family (Windows 10, Windows 11, Windows Server XXXX, etc.).

Sources:
  - Windows 10:     https://learn.microsoft.com/en-us/windows/release-health/release-information
  - Windows 11:     https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
  - Windows Server: https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info

Usage:
    python check_build.py                  # update data/win_builds.json
    python check_build.py --dry-run        # show what would change, don't write
    python check_build.py --wipe-clients   # delete data/known_clients.json (reset IP cache)
"""

import json
import os
import re
import datetime
import argparse
from urllib.request import urlopen, Request
from urllib.error import URLError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR    = os.path.join(_SCRIPT_DIR, "data")
_BUILDS_JSON = os.path.join(_DATA_DIR, "win_builds.json")
_CLIENTS_JSON = os.path.join(_DATA_DIR, "known_clients.json")

# Client sources: scrape "Version XXX (OS build NNNNN)" patterns
CLIENT_SOURCES = [
    {
        "url": "https://learn.microsoft.com/en-us/windows/release-health/release-information",
        "section": "Windows 10",
    },
    {
        "url": "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
        "section": "Windows 11",
    },
]

# Server source: scrape "Windows Server XXXX (OS build NNNNN)" headers
SERVER_SOURCE = {
    "url": "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info",
}

HEADERS = {
    "User-Agent": "check_build/1.0 (pywsus; build dictionary updater)",
    "Accept": "text/html",
}

# ---------------------------------------------------------------------------
# Scraping
# ---------------------------------------------------------------------------

def fetch_page(url):
    """Fetch a page and return its HTML as a string."""
    req = Request(url, headers=HEADERS)
    try:
        with urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except URLError as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        return ""


def extract_client_builds(html_content):
    """Extract { base_build: version_label } from a Win10/Win11 release health page.

    Looks for patterns like 'Version 22H2 (OS build 19045)'.
    """
    results = {}

    # Pattern 1: "Version 22H2 (OS build 19045)" style headers
    for m in re.finditer(
        r'Version\s+([\w.]+)\s*\(OS\s+build\s+(\d{5,})\)',
        html_content, re.IGNORECASE
    ):
        results[m.group(2)] = m.group(1)

    # Pattern 2: table rows with version + build pairs
    version_pat = re.compile(
        r'<td[^>]*>\s*(?:Version\s+)?(1[5-9]\d{2}|2[0-9]H[12]|2[0-9]{3})\s*</td>',
        re.IGNORECASE
    )
    build_pat = re.compile(r'<td[^>]*>\s*(\d{5,})(?:\.\d+)?\s*</td>')

    for row in re.finditer(r'<tr[^>]*>(.*?)</tr>', html_content, re.DOTALL):
        row_html = row.group(1)
        ver_m = version_pat.search(row_html)
        bld_m = build_pat.search(row_html)
        if ver_m and bld_m:
            build = bld_m.group(1)
            if build not in results:
                results[build] = ver_m.group(1)

    return results


def extract_server_builds(html_content):
    """Extract { section_name: { base_build: version } } from the Server page.

    Looks for detail headers like 'Windows Server 2025 (OS build 26100)'
    and main table rows like 'Windows Server 2019 (version 1809)'.
    """
    results = {}  # { "Windows Server 2025": { "26100": "24H2" }, ... }

    # Step 1: extract section → base_build from detail headers
    # Pattern: "Windows Server XXXX (OS build NNNNN)"
    section_builds = {}
    for m in re.finditer(
        r'Windows\s+Server\s+(\d{4})\s*\(OS\s+build\s+(\d{5,})\)',
        html_content, re.IGNORECASE
    ):
        name = f"Windows Server {m.group(1)}"
        base_build = m.group(2)
        section_builds[name] = base_build

    # Step 2: extract version from main table
    # Pattern: "Windows Server XXXX (version YYYY)" or just "Windows Server XXXX"
    version_map = {}
    for m in re.finditer(
        r'Windows\s+Server\s+(\d{4})\s*\(version\s+([\w.]+)\)',
        html_content, re.IGNORECASE
    ):
        version_map[f"Windows Server {m.group(1)}"] = m.group(2)

    # Step 3: for servers without explicit version, try to derive it
    # Server 2025 = build 26100 = "24H2", Server 2022 = build 20348 = "21H2"
    _KNOWN_SERVER_VERSIONS = {
        "Windows Server 2025": "24H2",
        "Windows Server 2022": "21H2",
    }

    # Combine
    for name, base_build in section_builds.items():
        version = version_map.get(name, _KNOWN_SERVER_VERSIONS.get(name, ""))
        if name not in results:
            results[name] = {}
        if version:
            results[name][base_build] = version

    return results


# ---------------------------------------------------------------------------
# JSON management
# ---------------------------------------------------------------------------

def load_json():
    """Load the existing data/win_builds.json or create a skeleton."""
    if os.path.exists(_BUILDS_JSON):
        with open(_BUILDS_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "_comment": "OS family → { build_number: version }. Updated by check_build.py",
        "_updated": "",
        "_sources": [s["url"] for s in CLIENT_SOURCES] + [SERVER_SOURCE["url"]],
    }


def save_json(data):
    """Write the updated JSON file with sorted builds per section."""
    data["_updated"] = datetime.date.today().isoformat()
    for key, val in data.items():
        if key.startswith("_") or not isinstance(val, dict):
            continue
        data[key] = dict(sorted(val.items(), key=lambda x: int(x[0])))
    os.makedirs(_DATA_DIR, exist_ok=True)
    with open(_BUILDS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
        f.write("\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Update data/win_builds.json from Microsoft release health pages.",
        epilog=(
            "Examples:\n"
            "  python check_build.py              # fetch latest builds\n"
            "  python check_build.py --dry-run     # preview without saving\n"
            "  python check_build.py --wipe-clients # reset known client IPs\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Show changes without writing to disk")
    parser.add_argument("--wipe-clients", action="store_true",
                        help="Reset data/known_clients.json (clear all known client IPs)")
    args = parser.parse_args()

    # --- Wipe clients if requested ---
    if args.wipe_clients:
        os.makedirs(_DATA_DIR, exist_ok=True)
        empty = {"_comment": "Known WSUS clients — { ip: {build, arch, os_desc} }. Auto-populated by pywsus."}
        with open(_CLIENTS_JSON, "w", encoding="utf-8") as f:
            json.dump(empty, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"[*] Cleared {_CLIENTS_JSON}")
        return

    data = load_json()
    added = {}

    # Count existing
    existing_count = sum(len(v) for k, v in data.items()
                         if not k.startswith("_") and isinstance(v, dict))
    print(f"[*] Current dictionary: {existing_count} builds in {_BUILDS_JSON}")
    print()

    # --- Client builds (Windows 10, Windows 11) ---
    for source in CLIENT_SOURCES:
        url     = source["url"]
        section = source["section"]

        print(f"[*] Fetching {section} release info...")
        html_content = fetch_page(url)
        if not html_content:
            continue

        discovered = extract_client_builds(html_content)
        print(f"    Found {len(discovered)} build(s) on page")

        existing = data.setdefault(section, {})
        for build, version in discovered.items():
            if build not in existing:
                added[f"{section}/{build}"] = version
                existing[build] = version
                print(f"    [+] NEW: {section} build {build} → version {version}")
            elif existing[build] != version:
                print(f"    [~] UPDATE: {section} build {build}: "
                      f"{existing[build]} → {version}")
                existing[build] = version
                added[f"{section}/{build}"] = version

    # --- Server builds ---
    print(f"[*] Fetching Windows Server release info...")
    html_content = fetch_page(SERVER_SOURCE["url"])
    if html_content:
        server_results = extract_server_builds(html_content)
        total_server = sum(len(v) for v in server_results.values())
        print(f"    Found {total_server} build(s) across {len(server_results)} server edition(s)")

        for section, builds in server_results.items():
            existing = data.setdefault(section, {})
            for build, version in builds.items():
                if build not in existing:
                    added[f"{section}/{build}"] = version
                    existing[build] = version
                    print(f"    [+] NEW: {section} build {build} → version {version}")
                elif existing[build] != version:
                    print(f"    [~] UPDATE: {section} build {build}: "
                          f"{existing[build]} → {version}")
                    existing[build] = version
                    added[f"{section}/{build}"] = version

    print()

    if not added:
        print("[*] Dictionary is already up to date, no new builds found.")
    else:
        print(f"[+] {len(added)} new/updated build(s):")
        for key, version in sorted(added.items()):
            print(f"    {key} → {version}")

    if added and not args.dry_run:
        save_json(data)
        print(f"\n[*] Saved to {_BUILDS_JSON}")
    elif added and args.dry_run:
        print(f"\n[*] Dry run — changes NOT saved")

    total = sum(len(v) for k, v in data.items()
                if not k.startswith("_") and isinstance(v, dict))
    families = sum(1 for k in data if not k.startswith("_") and isinstance(data[k], dict))
    print(f"\n[*] Total: {total} builds / {families} OS families")


if __name__ == "__main__":
    main()