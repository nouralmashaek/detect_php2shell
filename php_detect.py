
import argparse
import csv
import json
import re
import sys
from datetime import date
from urllib.parse import urljoin

import requests


HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; PHP-Detect/1.0; +internal-security-check)"
}

TIMEOUT = 10

PHP_ERROR_PATTERNS = [
    r"Fatal error:.*on line \d+",
    r"Warning:.*on line \d+",
    r"Notice:.*on line \d+",
    r"Parse error:.*on line \d+",
    r"<b>Fatal error</b>",
    r"Stack trace\).*#\d+ \{main\}",
]


# Source: https://www.php.net/supported-versions.php — re-check periodically,
# this list is only as current as when this script was last updated.
SUPPORT_CYCLE = {
    "7.4": {"active_until": date(2021, 11, 28), "security_until": date(2022, 11, 28)},
    "8.0": {"active_until": date(2022, 11, 26), "security_until": date(2023, 11, 26)},
    "8.1": {"active_until": date(2023, 11, 25), "security_until": date(2025, 12, 31)},
    "8.2": {"active_until": date(2024, 12, 31), "security_until": date(2026, 12, 31)},
    "8.3": {"active_until": date(2025, 12, 31), "security_until": date(2027, 12, 31)},
    "8.4": {"active_until": date(2026, 12, 31), "security_until": date(2028, 12, 31)},
    "8.5": {"active_until": date(2027, 12, 31), "security_until": date(2029, 12, 31)},
}

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "gray": "\033[90m",
}


def c(text: str, color: str) -> str:

    return f"{ANSI.get(color, '')}{text}{ANSI['reset']}"


def support_status(version: str) -> dict:

    m = re.match(r"(\d+)\.(\d+)", version or "")
    if not m:
        return {"branch": None, "status": "Unknown version format", "detail": ""}

    branch = f"{m.group(1)}.{m.group(2)}"
    cycle = SUPPORT_CYCLE.get(branch)
    today = date.today()

    if not cycle:
        return {
            "branch": branch,
            "status": "Not in known support table (likely very old / EOL)",
            "detail": "Treat as unsupported until confirmed otherwise.",
        }

    if today <= cycle["active_until"]:
        return {"branch": branch, "status": "Actively supported",
                "detail": f"Active support until {cycle['active_until']}"}
    elif today <= cycle["security_until"]:
        return {"branch": branch, "status": "Security fixes only",
                "detail": f"Security-only support until {cycle['security_until']}"}
    else:
        return {"branch": branch, "status": "End of life — no updates",
                "detail": f"Security support ended {cycle['security_until']}"}


def check_url(url: str) -> dict:

    result = {
        "url": url,
        "reachable": False,
        "php_detected": False,
        "evidence": [],
        "php_version": None,
        "support": None,
        "error": None,
    }

    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        result["error"] = str(e)
        return result

    result["reachable"] = True

    def set_version(candidate):
        if candidate and not result["php_version"]:
            result["php_version"] = candidate

    # 1. X-Powered-By header
    powered_by = resp.headers.get("X-Powered-By", "")
    if "php" in powered_by.lower():
        result["php_detected"] = True
        result["evidence"].append(f"X-Powered-By header: {powered_by}")
        m = re.search(r"PHP/([\d.]+)", powered_by, re.IGNORECASE)
        if m:
            set_version(m.group(1))

    # 2. Server header
    server = resp.headers.get("Server", "")
    if "php" in server.lower():
        result["php_detected"] = True
        result["evidence"].append(f"Server header: {server}")
        m = re.search(r"PHP/([\d.]+)", server, re.IGNORECASE)
        if m:
            set_version(m.group(1))

    # 3. PHPSESSID cookie
    if any("phpsessid" in k.lower() for k in resp.cookies.keys()):
        result["php_detected"] = True
        result["evidence"].append("PHPSESSID cookie present")
    if "phpsessid" in resp.headers.get("Set-Cookie", "").lower():
        result["php_detected"] = True
        result["evidence"].append("PHPSESSID in Set-Cookie header")

    # 4. .php links/forms in page source
    php_refs = re.findall(r'["\'][^"\']*\.php[^"\']*["\']', resp.text)
    if php_refs:
        result["php_detected"] = True
        sample = sorted(set(php_refs))[:5]
        result["evidence"].append(f".php references in page source: {sample}")

    # 5. Leaked PHP error text
    for pattern in PHP_ERROR_PATTERNS:
        if re.search(pattern, resp.text, re.IGNORECASE):
            result["php_detected"] = True
            result["evidence"].append(f"PHP error pattern matched: {pattern}")
            break

    # 6. Harmless probes against common PHP entrypoints
    for probe in ("index.php", "info.php"):
        try:
            probe_url = urljoin(url, probe)
            probe_resp = requests.get(probe_url, headers=HEADERS, timeout=TIMEOUT)
            if probe_resp.status_code != 404:
                probe_powered_by = probe_resp.headers.get("X-Powered-By", "")
                if "php" in probe_powered_by.lower():
                    result["php_detected"] = True
                    result["evidence"].append(
                        f"{probe} responded ({probe_resp.status_code}) with X-Powered-By: {probe_powered_by}"
                    )
                    m = re.search(r"PHP/([\d.]+)", probe_powered_by, re.IGNORECASE)
                    if m:
                        set_version(m.group(1))
        except requests.RequestException:
            pass

    if result["php_version"]:
        result["support"] = support_status(result["php_version"])

    return result


def load_targets_from_file(path: str) -> list:
    targets = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "://" not in line:
                line = "https://" + line
            targets.append(line)
    return targets


def print_result(r: dict):
    print(c(f"\n{'─'*60}", "gray"))
    print(c(f"TARGET: ", "bold") + r["url"])

    if r["error"]:
        print(c(f"  ✖ ERROR: {r['error']}", "red"))
        return

    if not r["php_detected"]:
        print(c("  ○ No PHP indicators found", "gray") + c(" (inconclusive — passive check only)", "gray"))
        return

    print(c("  ✔ PHP DETECTED", "green"))

    if r["php_version"]:
        print(c(f"  Version:  ", "bold") + r["php_version"])
    else:
        print(c(f"  Version:  ", "bold") + c("not disclosed by server", "gray"))

    if r["support"]:
        s = r["support"]
        status_color = {
            "Actively supported": "green",
            "Security fixes only": "yellow",
        }.get(s["status"], "red")
        print(c(f"  Status:   ", "bold") + c(s["status"], status_color))
        if s["detail"]:
            print(c(f"            {s['detail']}", "gray"))
    elif r["php_version"]:
        print(c("  Status:   ", "bold") + c("could not match version to support table", "gray"))

    print(c("  Evidence:", "bold"))
    for ev in r["evidence"]:
        print(f"    - {ev}")


def print_summary(results: list):
    print(c(f"\n{'='*60}", "cyan"))
    print(c("SUMMARY", "bold"))
    print(c(f"{'='*60}", "cyan"))
    header = f"{'URL':<35} {'PHP?':<6} {'Version':<10} {'Status'}"
    print(c(header, "bold"))
    print(c("-" * len(header), "gray"))
    for r in results:
        url_disp = (r["url"][:32] + "...") if len(r["url"]) > 35 else r["url"]
        if r["error"]:
            print(f"{url_disp:<35} {'ERR':<6} {'-':<10} {r['error'][:30]}")
            continue
        php_flag = c("YES", "green") if r["php_detected"] else c("no", "gray")
        version = r["php_version"] or "-"
        status = r["support"]["status"] if r["support"] else ("-" if not r["php_detected"] else "unknown")
        print(f"{url_disp:<35} {php_flag:<15} {version:<10} {status}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Passive, read-only PHP detection.")
    parser.add_argument("url", nargs="?", help="Single URL to check")
    parser.add_argument("-l", "--list", help="File with one URL per line")
    parser.add_argument("--json", help="Write results to this JSON file")
    parser.add_argument("--csv", help="Write results to this CSV file")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        targets.extend(load_targets_from_file(args.list))

    results = []
    for t in targets:
        r = check_url(t)
        results.append(r)
        print_result(r)

    print_summary(results)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON report written to {args.json}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "reachable", "php_detected", "php_version", "support_status", "evidence", "error"])
            for r in results:
                writer.writerow([
                    r["url"], r["reachable"], r["php_detected"],
                    r["php_version"] or "",
                    r["support"]["status"] if r["support"] else "",
                    " | ".join(r["evidence"]), r["error"] or ""
                ])
        print(f"CSV report written to {args.csv}")


if __name__ == "__main__":
    main()
