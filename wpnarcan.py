"""WP Narcan - WordPress Malware Recovery Tool

Rebuilds a compromised WordPress installation by downloading fresh copies
of core files, plugins, and themes from the official WordPress repository.
"""

from __future__ import annotations

import os
import re
import argparse
import logging
import zipfile
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WP_CORE_URL = "https://wordpress.org/latest.zip"
WP_DOWNLOAD_URL_TEMPLATE = "https://downloads.wordpress.org/{content_type}/{item}.zip"

SUSPICIOUS_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phtml", ".phar", ".phps",
    ".htaccess", ".htpasswd",
    ".exe", ".bat", ".cmd", ".ps1",
    ".cgi", ".pl",
    ".asp", ".aspx", ".jsp",
    ".sh",
]

SUSPICIOUS_FILENAMES = [
    ".user.ini",
    "php.ini",
    ".htaccess",
    ".htpasswd",
]

KNOWN_DROP_INS = [
    "advanced-cache.php",
    "db.php",
    "object-cache.php",
    "sunrise.php",
    "blog-deleted.php",
    "blog-inactive.php",
    "blog-suspended.php",
    "maintenance.php",
    "install.php",
]

DEFAULT_WP_CONTENT_DIR = "wp-content"

SILENCE_IS_GOLDEN_CONTENT = "<?php\n// Silence is golden.\n"

WP_CONFIG_SUSPICIOUS_PATTERNS = [
    (r"eval\s*\(", "eval() call - may execute injected code"),
    (r"base64_decode\s*\(", "base64_decode() - commonly used to obfuscate malware"),
    (r"gzinflate\s*\(", "gzinflate() - commonly used to obfuscate malware"),
    (r"str_rot13\s*\(", "str_rot13() - commonly used to obfuscate malware"),
    (r"file_get_contents\s*\(", "file_get_contents() - may load external malicious code"),
    (r"curl_exec\s*\(", "curl_exec() - may communicate with external servers"),
    (r"\bexec\s*\(", "exec() - may execute system commands"),
    (r"\bsystem\s*\(", "system() - may execute system commands"),
    (r"passthru\s*\(", "passthru() - may execute system commands"),
    (r"shell_exec\s*\(", "shell_exec() - may execute system commands"),
    (r"\bassert\s*\(", "assert() - can be used as eval alternative"),
    (r"preg_replace\s*\(.*/e", "preg_replace with /e modifier - executes code"),
    (r"\$_(GET|POST|REQUEST|COOKIE)\s*\[", "Direct superglobal access - unusual in wp-config.php"),
]

REQUEST_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
DOWNLOAD_CHUNK_SIZE = 8192
MAX_DOWNLOAD_WORKERS = 4

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("wpnarcan")


def setup_logging(log_file: Optional[str] = None) -> None:
    """Configure logging to console and optionally to a file."""
    logger.setLevel(logging.DEBUG)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def create_session() -> requests.Session:
    """Create a requests session with automatic retry on transient errors."""
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ---------------------------------------------------------------------------
# WordPress helpers
# ---------------------------------------------------------------------------

def is_valid_wp_directory(directory: str, wp_content: str = DEFAULT_WP_CONTENT_DIR) -> bool:
    """Return True if *directory* looks like a WordPress installation."""
    required = [
        os.path.isfile(os.path.join(directory, "wp-config.php")),
        os.path.isdir(os.path.join(directory, wp_content)),
        os.path.isdir(os.path.join(directory, wp_content, "themes")),
        os.path.isdir(os.path.join(directory, wp_content, "plugins")),
    ]
    return all(required)


def download_and_extract(
    url: str,
    extract_to: str,
    session: requests.Session,
    is_wp: bool = False,
) -> None:
    """Download a zip archive from *url* and extract it into *extract_to*."""
    try:
        response = session.get(url, stream=True, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.ConnectionError:
        raise Exception("Connection failed - check your network")
    except requests.Timeout:
        raise Exception(f"Request timed out after {REQUEST_TIMEOUT}s")
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            raise Exception("Not found in WordPress repository")
        raise Exception(f"HTTP error: {e}")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_file:
        for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
            tmp_file.write(chunk)
        tmp_path = tmp_file.name

    try:
        with zipfile.ZipFile(tmp_path, "r") as zip_ref:
            if is_wp:
                zip_ref.extractall(extract_to)
                wp_dir = os.path.join(extract_to, "wordpress")
                for filename in os.listdir(wp_dir):
                    shutil.move(os.path.join(wp_dir, filename), extract_to)
                os.rmdir(wp_dir)
            else:
                zip_ref.extractall(extract_to)
    except zipfile.BadZipFile:
        raise Exception("Downloaded file is not a valid zip archive")
    finally:
        os.remove(tmp_path)


def prompt_for_confirmation(items: list[str], content_type: str) -> bool:
    """Display *items* and ask the user whether to proceed."""
    logger.info("Found %d %s(s):", len(items), content_type)
    for item in items:
        logger.info("  - %s", item)
    answer = input(
        f"Download and install these {content_type}(s)? (y/n): "
    ).strip().lower()
    return answer == "y"


def extract_local_zip(zip_path: str, extract_to: str) -> None:
    """Extract a local zip archive into *extract_to*."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_to)
    except zipfile.BadZipFile:
        raise Exception(f"Local file is not a valid zip archive: {zip_path}")


def _download_single_item(
    item: str,
    content_type: str,
    dest_path: str,
    session: requests.Session,
    local_repo: Optional[str] = None,
) -> tuple[str, bool, str]:
    """Install one plugin/theme. Checks local repo first, then WordPress.org.

    Returns (name, success, message).
    """
    # Try local repo first
    if local_repo:
        local_zip = os.path.join(local_repo, f"{item}.zip")
        if os.path.isfile(local_zip):
            try:
                extract_local_zip(local_zip, dest_path)
                return (item, True, f"Installed {content_type} from local repo: {item}")
            except Exception as e:
                return (item, False, f"Error extracting local {content_type} '{item}': {e}")

    # Fall back to WordPress.org
    url = WP_DOWNLOAD_URL_TEMPLATE.format(content_type=content_type, item=item)
    try:
        download_and_extract(url, dest_path, session)
        return (item, True, f"Downloaded {content_type}: {item}")
    except Exception as e:
        return (item, False, f"Error downloading {content_type} '{item}': {e}")


def handle_wp_content(
    content_type: str,
    source_dir: str,
    dest_dir: str,
    session: requests.Session,
    report: dict,
    local_repo: Optional[str] = None,
    wp_content: str = DEFAULT_WP_CONTENT_DIR,
) -> None:
    """Install clean copies of all plugins or themes found in *source_dir*.

    If *local_repo* is provided, zip files in that directory are checked first
    before falling back to the WordPress.org repository.
    """
    source_path = os.path.join(source_dir, wp_content, content_type + "s")
    dest_path = os.path.join(dest_dir, wp_content, content_type + "s")
    os.makedirs(dest_path, exist_ok=True)

    if not os.path.isdir(source_path):
        logger.warning("Source %ss directory not found: %s", content_type, source_path)
        return

    items = [
        name for name in os.listdir(source_path)
        if os.path.isdir(os.path.join(source_path, name))
    ]

    if not items:
        logger.info("No %ss found.", content_type)
        return

    if not prompt_for_confirmation(items, content_type):
        logger.info("Skipping %s download.", content_type)
        return

    missing_items: list[str] = []
    succeeded = 0

    if local_repo:
        logger.info("Local repo: %s", local_repo)

    with ThreadPoolExecutor(max_workers=MAX_DOWNLOAD_WORKERS) as pool:
        futures = {
            pool.submit(_download_single_item, item, content_type, dest_path, session, local_repo): item
            for item in items
        }
        for i, future in enumerate(as_completed(futures), 1):
            name, success, message = future.result()
            logger.info("  [%d/%d] %s", i, len(items), message)
            if success:
                succeeded += 1
            else:
                missing_items.append(name)

    report[f"{content_type}s_found"] = len(items)
    report[f"{content_type}s_downloaded"] = succeeded
    report[f"{content_type}s_missing"] = missing_items

    if missing_items:
        missing_file = os.path.join(dest_path, "missing.txt")
        with open(missing_file, "w") as f:
            f.write("\n".join(missing_items))
        logger.info("Missing %s(s) listed in %s", content_type, missing_file)


# ---------------------------------------------------------------------------
# Upload scanning
# ---------------------------------------------------------------------------

def is_silence_is_golden_file(file_path: str) -> bool:
    """Return True if *file_path* is a WordPress 'Silence is golden' stub."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(1024)
            return content == SILENCE_IS_GOLDEN_CONTENT
    except IOError:
        return False


def scan_and_clean_uploads(uploads_dir: str, report: dict) -> None:
    """Remove suspicious executable files from the uploads directory."""
    logger.info("Scanning uploads directory: %s", uploads_dir)
    deleted: list[str] = []
    failed: list[tuple[str, str]] = []

    for root, _dirs, files in os.walk(uploads_dir):
        for file in files:
            file_path = os.path.join(root, file)
            is_suspicious_ext = any(file.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
            is_suspicious_name = file.lower() in SUSPICIOUS_FILENAMES
            if is_suspicious_ext or is_suspicious_name:
                if not is_silence_is_golden_file(file_path):
                    try:
                        os.remove(file_path)
                        deleted.append(file_path)
                        logger.info("  Deleted: %s", file_path)
                    except OSError as e:
                        failed.append((file_path, str(e)))
                        logger.warning("  Failed to delete %s: %s", file_path, e)

    report["uploads_deleted"] = deleted
    report["uploads_delete_failed"] = failed


# ---------------------------------------------------------------------------
# mu-plugins handling
# ---------------------------------------------------------------------------

def handle_mu_plugins(
    source_dir: str,
    dest_dir: str,
    wp_content: str,
    report: dict,
) -> None:
    """Copy mu-plugins and scan them for suspicious content.

    mu-plugins auto-load without activation, making them a common malware
    hiding spot.  Since they are not available on WordPress.org, we copy
    them from the original installation and scan each file for suspicious
    patterns.
    """
    source_path = os.path.join(source_dir, wp_content, "mu-plugins")
    dest_path = os.path.join(dest_dir, wp_content, "mu-plugins")

    if not os.path.isdir(source_path):
        logger.info("No mu-plugins directory found, skipping.")
        return

    files = [f for f in os.listdir(source_path) if os.path.isfile(os.path.join(source_path, f))]
    dirs = [d for d in os.listdir(source_path) if os.path.isdir(os.path.join(source_path, d))]

    if not files and not dirs:
        logger.info("mu-plugins directory is empty, skipping.")
        return

    logger.info("Found %d mu-plugin file(s) and %d subdirectory(ies):", len(files), len(dirs))
    for f in files:
        logger.info("  - %s", f)
    for d in dirs:
        logger.info("  - %s/", d)

    shutil.copytree(source_path, dest_path, dirs_exist_ok=True)

    # Scan all PHP files for suspicious patterns
    warnings: dict[str, list[str]] = {}
    for root, _dirs, filenames in os.walk(dest_path):
        for filename in filenames:
            if filename.lower().endswith((".php", ".phtml", ".phar")):
                file_path = os.path.join(root, filename)
                file_warnings = scan_wp_config(file_path)  # reuse pattern scanner
                if file_warnings:
                    rel_path = os.path.relpath(file_path, dest_path)
                    warnings[rel_path] = file_warnings

    report["mu_plugins_copied"] = len(files) + len(dirs)
    report["mu_plugins_warnings"] = warnings

    if warnings:
        logger.warning("WARNING: Suspicious patterns found in mu-plugins:")
        for path, warns in warnings.items():
            logger.warning("  %s:", path)
            for w in warns:
                logger.warning("    - %s", w)
        logger.warning("Review all mu-plugins carefully before use.")
    else:
        logger.info("Copied mu-plugins, no suspicious patterns detected.")


# ---------------------------------------------------------------------------
# Drop-ins scanning
# ---------------------------------------------------------------------------

def handle_drop_ins(
    source_dir: str,
    dest_dir: str,
    wp_content: str,
    report: dict,
) -> None:
    """Scan and copy known WordPress drop-in files from wp-content/.

    Drop-in files are single PHP files in the wp-content root that WordPress
    loads automatically (e.g. advanced-cache.php, db.php, object-cache.php).
    They are a common malware target.
    """
    source_wpc = os.path.join(source_dir, wp_content)
    dest_wpc = os.path.join(dest_dir, wp_content)

    found_drop_ins: list[str] = []
    warnings: dict[str, list[str]] = {}

    # Check known drop-ins
    for drop_in in KNOWN_DROP_INS:
        src = os.path.join(source_wpc, drop_in)
        if os.path.isfile(src):
            found_drop_ins.append(drop_in)

    # Also flag unexpected PHP files in wp-content root
    unexpected: list[str] = []
    if os.path.isdir(source_wpc):
        for f in os.listdir(source_wpc):
            full = os.path.join(source_wpc, f)
            if os.path.isfile(full) and f.lower().endswith(".php"):
                if f not in KNOWN_DROP_INS and f != "index.php":
                    unexpected.append(f)

    if not found_drop_ins and not unexpected:
        logger.info("No drop-in files found.")
        report["drop_ins_copied"] = []
        report["drop_ins_warnings"] = {}
        report["drop_ins_unexpected"] = []
        return

    if found_drop_ins:
        logger.info("Found %d drop-in file(s):", len(found_drop_ins))
        for d in found_drop_ins:
            logger.info("  - %s", d)

    if unexpected:
        logger.warning("Found %d unexpected PHP file(s) in %s/:", len(unexpected), wp_content)
        for u in unexpected:
            logger.warning("  - %s (not a known drop-in)", u)

    # Copy and scan each drop-in
    os.makedirs(dest_wpc, exist_ok=True)
    for drop_in in found_drop_ins:
        src = os.path.join(source_wpc, drop_in)
        dst = os.path.join(dest_wpc, drop_in)
        shutil.copy2(src, dst)
        file_warnings = scan_wp_config(src)
        if file_warnings:
            warnings[drop_in] = file_warnings

    report["drop_ins_copied"] = found_drop_ins
    report["drop_ins_warnings"] = warnings
    report["drop_ins_unexpected"] = unexpected

    if warnings:
        logger.warning("WARNING: Suspicious patterns found in drop-in files:")
        for path, warns in warnings.items():
            logger.warning("  %s:", path)
            for w in warns:
                logger.warning("    - %s", w)
        logger.warning("Review all drop-in files carefully before use.")
    elif found_drop_ins:
        logger.info("Copied drop-ins, no suspicious patterns detected.")


# ---------------------------------------------------------------------------
# wp-config.php scanning
# ---------------------------------------------------------------------------

def scan_wp_config(file_path: str) -> list[str]:
    """Scan wp-config.php for patterns commonly associated with malware."""
    warnings: list[str] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for pattern, description in WP_CONFIG_SUSPICIOUS_PATTERNS:
            if re.search(pattern, content):
                warnings.append(description)
    except IOError as e:
        warnings.append(f"Could not read file: {e}")
    return warnings


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(report: dict) -> None:
    """Print a summary of everything that was done during recovery."""
    logger.info("=" * 60)
    logger.info("RECOVERY SUMMARY")
    logger.info("=" * 60)

    if "wp_core" in report:
        logger.info("  WordPress Core: %s", report["wp_core"])

    for ctype in ("plugin", "theme"):
        found = report.get(f"{ctype}s_found", 0)
        downloaded = report.get(f"{ctype}s_downloaded", 0)
        missing = report.get(f"{ctype}s_missing", [])
        if found:
            logger.info("  %ss: %d/%d downloaded", ctype.title(), downloaded, found)
            for item in missing:
                logger.info("    - MISSING: %s", item)

    deleted = report.get("uploads_deleted", [])
    failed = report.get("uploads_delete_failed", [])
    if deleted or failed:
        logger.info("  Uploads: %d suspicious file(s) removed", len(deleted))
        if failed:
            logger.info("  Uploads: %d file(s) could not be deleted", len(failed))

    mu_copied = report.get("mu_plugins_copied", 0)
    mu_warnings = report.get("mu_plugins_warnings", {})
    if mu_copied:
        logger.info("  mu-plugins: %d copied, %d with warnings", mu_copied, len(mu_warnings))

    drop_copied = report.get("drop_ins_copied", [])
    drop_warnings = report.get("drop_ins_warnings", {})
    drop_unexpected = report.get("drop_ins_unexpected", [])
    if drop_copied or drop_unexpected:
        logger.info("  Drop-ins: %d copied, %d with warnings", len(drop_copied), len(drop_warnings))
        if drop_unexpected:
            logger.info("  Drop-ins: %d unexpected PHP file(s) in wp-content/", len(drop_unexpected))

    config_warnings = report.get("wp_config_warnings", [])
    if config_warnings:
        logger.info(
            "  wp-config.php: %d WARNING(s) - review carefully!", len(config_warnings)
        )
    else:
        logger.info("  wp-config.php: no suspicious patterns detected")

    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point for WP Narcan."""
    parser = argparse.ArgumentParser(description="Rebuild a WordPress installation.")
    parser.add_argument("directory", type=str, help="Path to the WordPress directory")
    parser.add_argument(
        "--local-repo-plugins",
        type=str,
        default=None,
        help="Path to a local directory containing plugin zip files. "
             "Each zip must be named to match the plugin folder name "
             "(e.g. akismet.zip for the akismet plugin). Local zips are "
             "tried first; if not found, the WordPress.org repository is "
             "used as a fallback.",
    )
    parser.add_argument(
        "--local-repo-themes",
        type=str,
        default=None,
        help="Path to a local directory containing theme zip files. "
             "Each zip must be named to match the theme folder name "
             "(e.g. flavor.zip for the flavor theme). Local zips are "
             "tried first; if not found, the WordPress.org repository is "
             "used as a fallback.",
    )
    parser.add_argument(
        "--wp-content-dir",
        type=str,
        default=DEFAULT_WP_CONTENT_DIR,
        help="Name of the wp-content directory if it has been renamed "
             "from the default (default: wp-content). This is the folder "
             "name relative to the WordPress root, not an absolute path.",
    )
    args = parser.parse_args()

    # Validate local repo paths early
    for label, path in [("plugins", args.local_repo_plugins), ("themes", args.local_repo_themes)]:
        if path and not os.path.isdir(path):
            print(f"Error: Local {label} repo path does not exist: {path}")
            return

    original_dir_path = os.path.abspath(args.directory)
    parent_dir = os.path.dirname(original_dir_path)
    directory_name = os.path.basename(original_dir_path)
    new_dir = os.path.join(parent_dir, f"{directory_name}-rebuilt")

    os.makedirs(new_dir, exist_ok=True)

    log_file = os.path.join(new_dir, "wpnarcan.log")
    setup_logging(log_file)

    logger.info("Welcome to WP Narcan")
    logger.info("Author: ReignOfComputer")
    logger.info("")

    wp_content = args.wp_content_dir

    if not is_valid_wp_directory(args.directory, wp_content):
        logger.error(
            "Invalid WordPress directory. Ensure wp-config.php, %s/, "
            "%s/themes/, and %s/plugins/ all exist.",
            wp_content, wp_content, wp_content,
        )
        return

    logger.info("Found valid WordPress installation.")
    logger.info("Rebuilding into: %s", new_dir)

    session = create_session()
    report: dict = {}

    # WordPress core
    try:
        download_and_extract(WP_CORE_URL, new_dir, session, is_wp=True)
        report["wp_core"] = "Downloaded"
        logger.info("Downloaded WordPress core.")
    except Exception as e:
        report["wp_core"] = f"FAILED: {e}"
        logger.error("Failed to download WordPress core: %s", e)
        return

    logger.info("")

    # Plugins and themes
    local_repos = {
        "plugin": args.local_repo_plugins,
        "theme": args.local_repo_themes,
    }
    for content_type in ("plugin", "theme"):
        handle_wp_content(
            content_type, args.directory, new_dir, session, report,
            local_repo=local_repos[content_type],
            wp_content=wp_content,
        )
        logger.info("")

    # mu-plugins
    handle_mu_plugins(args.directory, new_dir, wp_content, report)
    logger.info("")

    # Drop-ins
    handle_drop_ins(args.directory, new_dir, wp_content, report)
    logger.info("")

    # Uploads
    uploads_dir = os.path.join(args.directory, wp_content, "uploads")
    rebuilt_uploads_dir = os.path.join(new_dir, wp_content, "uploads")
    if os.path.exists(uploads_dir):
        shutil.copytree(uploads_dir, rebuilt_uploads_dir, dirs_exist_ok=True)
        scan_and_clean_uploads(rebuilt_uploads_dir, report)
    else:
        logger.info("No uploads directory found, skipping.")

    logger.info("")

    # wp-config.php
    wp_config_src = os.path.join(original_dir_path, "wp-config.php")
    wp_config_dest = os.path.join(new_dir, "wp-config.php")
    if os.path.exists(wp_config_src):
        config_warnings = scan_wp_config(wp_config_src)
        report["wp_config_warnings"] = config_warnings

        if config_warnings:
            logger.warning("WARNING: Suspicious patterns found in wp-config.php:")
            for w in config_warnings:
                logger.warning("  - %s", w)
            logger.warning(
                "The file will still be copied, but review it carefully before use."
            )

        shutil.copy(wp_config_src, wp_config_dest)
        logger.info("Copied wp-config.php to rebuilt directory.")
    else:
        logger.error("wp-config.php not found in original directory.")
        report["wp_config_warnings"] = ["File not found"]

    logger.info("")

    # Summary
    print_report(report)
    logger.info("")
    logger.info(
        "Take note of any missing items and manually verify files "
        "before replacing your server copy."
    )
    logger.info("Full log saved to: %s", log_file)


if __name__ == "__main__":
    main()
