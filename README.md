
PHP Detection Script

php_detect.py — passive, read-only PHP fingerprinting tool.

Usage:
    python3 php_detect.py https://example.com
    python3 php_detect.py -l targets.txt
    python3 php_detect.py https://example.com --json out.json
"""

Purpose: A passive, read-only Python tool to check whether a given web server is running PHP, and if so, what version and support status.

How it works: The script sends standard HTTP GET requests to each target URL — the same kind of request any web browser makes — and inspects the response for publicly visible indicators of PHP:

X-Powered-By and Server response headers (often reveal the PHP version directly)
PHPSESSID session cookies, which PHP sets by default
.php file references in the page’s HTML source
PHP-style error messages that may be exposed due to misconfiguration
Response behavior from common PHP entry points (e.g. index.php, info.php)

If a version number is found, it is cross-checked against PHP’s officially published support lifecycle (php.net/supported-versions.php) to flag whether that version is actively supported,
in security-only support, or end-of-life.

What it does NOT do: It sends no malformed, malicious, or exploit payloads, and makes no attempt to execute code, authenticate, or alter anything on the target. 
It is strictly observational — equivalent to inspecting a page in a browser’s developer tools.

Output: Per-target findings (detected/not detected, version, support status, evidence) printed to console, plus optional JSON/CSV export for multiple targets
usable in batch via a target list file.

Limitation to note in the report: Detection relies on information the server voluntarily exposes. 
A hardened server (headers stripped, error display disabled, no .php extensions visible) 
can show “no indicators found” even while running PHP internally 
— a negative result is not a guarantee of absence, and should be confirmed with direct server access (e.g. checking installed packages) where certainty is required.
