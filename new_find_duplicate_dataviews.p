#!/usr/bin/env python3
"""
Find Duplicate Data Views Across Multiple Kibana Deployments

This script loops through multiple Elasticsearch/Kibana deployments (read from a
JSON config file), scans all spaces in each deployment, and identifies duplicate
data views (same title appearing multiple times within a space). For each
duplicate it reports:
  - Deployment name
  - Kibana space
  - Data view title and IDs
  - Number of saved-object references per data view ID
  - KEEP / SAFE TO DELETE recommendations
  - Default data view warnings

Usage:
    # Scan ALL clusters (uses clusters.json in current directory by default)
    python find_duplicate_dataviews.py

    # Use a custom config file
    python find_duplicate_dataviews.py --config /path/to/my_clusters.json

    # Scan specific clusters only
    python find_duplicate_dataviews.py --clusters prod qa

    # Scan specific spaces within a cluster
    python find_duplicate_dataviews.py --clusters "FISMA Scorecard" --spaces "FISMA Team"

    # Test connectivity without scanning
    python find_duplicate_dataviews.py --connectivity-check

    # Export results to CSV
    python find_duplicate_dataviews.py --output csv

    # Run with concurrent workers for speed
    python find_duplicate_dataviews.py --workers 5

    # Preview which orphaned data views would be deleted
    python find_duplicate_dataviews.py --dry-run-delete

    # Show top offender spaces ranked by duplicate count
    python find_duplicate_dataviews.py --top-offenders

    # Write logs to a file alongside stdout
    python find_duplicate_dataviews.py --log-file scan.log

Config file format (clusters.json):
{
  "clusters": {
    "prod": {
      "kibana_url": "https://prod-kibana:5601",
      "api_key": "YOUR_API_KEY_HERE",
      "verify_ssl": false,
      "description": "Production cluster"
    }
  }
}

API keys can also be referenced as environment variables:
    "api_key": "$PROD_KIBANA_API_KEY"
"""

import sys
import os
import requests
import logging
import json
import csv
import time
import shutil
from collections import defaultdict
from argparse import ArgumentParser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==============================================================================
# PROGRESS BAR
# ==============================================================================

class ProgressBar:
    """
    A simple terminal progress bar that shows cluster/space scan progress.
    Works without external dependencies. Auto-detects terminal width.

    Usage:
        pb = ProgressBar(total=10, prefix="Scanning clusters")
        for i in range(10):
            pb.update(i + 1, status="prod - Team Alpha")
        pb.finish()
    """

    def __init__(self, total, prefix="Progress"):
        self.total = total
        self.prefix = prefix
        self.start_time = time.time()
        self.current = 0
        self.terminal_width = shutil.get_terminal_size((80, 20)).columns

    def update(self, current, status=""):
        self.current = current
        elapsed = time.time() - self.start_time
        pct = current / self.total if self.total > 0 else 1.0
        filled = int(30 * pct)
        bar = "█" * filled + "░" * (30 - filled)

        # Estimate time remaining
        if pct > 0 and current > 0:
            eta = elapsed / pct - elapsed
            time_str = f"ETA {self._fmt_time(eta)}"
        else:
            time_str = "ETA --:--"

        elapsed_str = self._fmt_time(elapsed)
        status_display = f" | {status}" if status else ""

        # Build the line and truncate to terminal width
        line = f"\r  {self.prefix} |{bar}| {current}/{self.total} ({pct:.0%}) [{elapsed_str} < {time_str}]{status_display}"
        line = line[:self.terminal_width - 1]
        # Pad with spaces to overwrite previous longer lines
        line = line.ljust(self.terminal_width - 1)
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self, summary=""):
        elapsed = time.time() - self.start_time
        elapsed_str = self._fmt_time(elapsed)
        line = f"\r  {self.prefix} |{'█' * 30}| {self.total}/{self.total} (100%) [{elapsed_str}] ✅ Done"
        if summary:
            line += f" — {summary}"
        line = line[:self.terminal_width - 1].ljust(self.terminal_width - 1)
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    @staticmethod
    def _fmt_time(seconds):
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            m, s = divmod(int(seconds), 60)
            return f"{m}m{s:02d}s"
        else:
            h, remainder = divmod(int(seconds), 3600)
            m, s = divmod(remainder, 60)
            return f"{h}h{m:02d}m"


# ==============================================================================
# CONFIGURATION
# ==============================================================================

def load_config(config_path):
    """
    Load cluster configuration from a JSON file.
    Resolves environment variable references in api_key values.

    Args:
        config_path (str): Path to the JSON config file

    Returns:
        dict: Parsed and resolved configuration
    """
    if not os.path.exists(config_path):
        logging.error(f"Config file not found: {config_path}")
        sys.exit(1)

    with open(config_path, 'r') as f:
        config = json.load(f)

    clusters = config.get("clusters", {})
    if not clusters:
        logging.error("No clusters defined in config file.")
        sys.exit(1)

    # Resolve environment variable references for api_key
    for name, cluster in clusters.items():
        api_key = cluster.get("api_key", "")
        if api_key.startswith("$"):
            env_var = api_key[1:]
            resolved = os.environ.get(env_var)
            if not resolved:
                logging.warning(f"[{name}] Environment variable '{env_var}' not set. Skipping cluster.")
                cluster["api_key"] = None
            else:
                cluster["api_key"] = resolved

        # Default verify_ssl to True if not specified
        if "verify_ssl" not in cluster:
            cluster["verify_ssl"] = True

        # Strip trailing slashes from kibana_url to prevent double-slash URLs
        if "kibana_url" in cluster:
            cluster["kibana_url"] = cluster["kibana_url"].rstrip("/")

    return config


def validate_cluster_config(name, cluster):
    """Validate that a cluster config has required fields."""
    required = ["kibana_url", "api_key"]
    for field in required:
        if not cluster.get(field):
            logging.warning(f"[{name}] Missing or empty '{field}'. Skipping.")
            return False
    return True


# ==============================================================================
# KIBANA API HELPERS
# ==============================================================================

# Initialize Kibana object types to be processed
def get_object_types():
    object_types = [
        "config", "config-global", "url", "index-pattern", "action", "query",
        "tag", "graph-workspace", "alert", "search", "visualization",
        "event-annotation-group", "dashboard", "lens", "cases",
        "metrics-data-source", "links", "canvas-element", "canvas-workpad",
        "osquery-saved-query", "osquery-pack", "csp-rule-template", "map",
        "infrastructure-monitoring-log-view", "threshold-explorer-view",
        "uptime-dynamic-settings", "synthetics-privates-locations",
        "apm-indices", "infrastructure-ui-source", "inventory-view",
        "infra-custom-dashboards", "metrics-explorer-view", "apm-service-group",
        "apm-custom-dashboards"
    ]
    return object_types


def get_headers(api_key):
    """Set up headers for Kibana authentication."""
    return {
        'kbn-xsrf': 'true',
        'Content-Type': 'application/json',
        'Authorization': f'ApiKey {api_key}'
    }


def get_all_spaces(headers, kibana_url, verify_ssl=True):
    """
    Retrieve all Kibana spaces in a deployment.

    Args:
        headers (dict): Authentication headers
        kibana_url (str): Kibana base URL
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        list: List of space dicts with 'id' and 'name' keys
    """
    spaces_endpoint = f"{kibana_url}/api/spaces/space"
    try:
        response = requests.get(spaces_endpoint, headers=headers, verify=verify_ssl, timeout=30)
        response.raise_for_status()
        spaces = response.json()
        logging.info(f"  Found {len(spaces)} spaces")
        return spaces
    except requests.exceptions.RequestException as e:
        logging.error(f"  Failed to retrieve spaces: {e}")
        return []


def get_all_dataviews(space_id, headers, kibana_url, verify_ssl=True):
    """
    Get all data views in the specified space.

    Args:
        space_id (str): Kibana space ID
        headers (dict): Authentication headers
        kibana_url (str): Kibana base URL
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        list: List of data view dicts
    """
    dataview_url = f'{kibana_url}/s/{space_id}/api/data_views'
    try:
        response = requests.get(dataview_url, headers=headers, verify=verify_ssl, timeout=30)
        if response.status_code == 200:
            return response.json().get('data_view', [])
        else:
            logging.warning(f"    Failed to get data views in space '{space_id}': HTTP {response.status_code}")
            return []
    except requests.exceptions.RequestException as e:
        logging.warning(f"    Failed to get data views in space '{space_id}': {e}")
        return []


def get_default_dataview_id(space_id, headers, kibana_url, verify_ssl=True):
    """
    Get the default data view ID for a Kibana space.

    Args:
        space_id (str): Kibana space ID
        headers (dict): Authentication headers
        kibana_url (str): Kibana base URL
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        str or None: The default data view ID, or None if unavailable
    """
    default_url = f'{kibana_url}/s/{space_id}/api/data_views/default'
    try:
        response = requests.get(default_url, headers=headers, verify=verify_ssl, timeout=15)
        if response.status_code == 200:
            data = response.json()
            return data.get("data_view_id") or None
        return None
    except requests.exceptions.RequestException:
        return None


def find_duplicated_data_views(data_views):
    """
    Find data views with duplicate titles.

    Args:
        data_views (list): List of data view dicts

    Returns:
        dict: {title: [list of IDs]} for titles with more than one ID
    """
    title_to_ids = defaultdict(list)
    for dv in data_views:
        title = dv.get("title")
        if not title:
            logging.warning(f"    Skipping data view '{dv.get('id', 'unknown')}' — missing title")
            continue
        title_to_ids[title].append(dv["id"])
    return {title: ids for title, ids in title_to_ids.items() if len(ids) > 1}


def _request_with_retry(url, headers, params=None, verify=True, timeout=30, max_retries=3):
    """
    Make a GET request with retry logic and exponential backoff.

    Args:
        url (str): Request URL
        headers (dict): Request headers
        params (dict|list): Query parameters (use list of tuples for repeated keys)
        verify (bool): SSL verification
        timeout (int): Request timeout in seconds
        max_retries (int): Maximum number of retry attempts

    Returns:
        requests.Response or None on total failure
    """
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url, headers=headers, params=params,
                verify=verify, timeout=timeout
            )
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            wait = 2 ** attempt
            logging.warning(f"    Timeout on {url} (attempt {attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.ConnectionError:
            wait = 2 ** attempt
            logging.warning(f"    Connection error on {url} (attempt {attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.HTTPError as e:
            # Don't retry on 4xx client errors (except 429 rate-limit)
            if response is not None and 400 <= response.status_code < 500 and response.status_code != 429:
                logging.debug(f"    HTTP {response.status_code} on {url} — not retrying")
                return response
            wait = 2 ** attempt
            logging.warning(f"    HTTP error on {url} (attempt {attempt+1}/{max_retries}): {e}, retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.RequestException as e:
            logging.warning(f"    Request failed on {url}: {e}")
            return None
    logging.error(f"    All {max_retries} retries exhausted for {url}")
    return None


def get_object_references(data_view_ids, kibana_url, space_id, object_types, headers, verify_ssl=True):
    """
    Count saved-object references to each data view ID.

    Performance: Instead of making 30+ separate HTTP calls (one per object type),
    this sends ALL types in a single batched API call using repeated 'type' query
    parameters. The Kibana _find API accepts type as a string|array, so passing
    multiple type=X&type=Y params returns all matching objects in one response.

    For spaces with many saved objects, results are paginated automatically.

    Args:
        data_view_ids (list): Data view IDs to check references for
        kibana_url (str): Kibana base URL
        space_id (str): Space ID
        object_types (list): Kibana object types to scan
        headers (dict): Authentication headers
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        dict: {data_view_id: reference_count}
    """
    objects_endpoint = f"{kibana_url}/s/{space_id}/api/saved_objects/_find"
    reference_counts = defaultdict(int)
    data_view_id_set = set(data_view_ids)

    # Build params as a list of tuples so 'type' can be repeated:
    # type=dashboard&type=visualization&type=lens&...
    # This sends ALL object types in a single HTTP request.
    base_params = [('fields', 'references'), ('per_page', '10000')]
    for ot in object_types:
        base_params.append(('type', ot))

    page = 1
    total_fetched = 0

    while True:
        params = base_params + [('page', str(page))]

        response = _request_with_retry(
            objects_endpoint, headers=headers, params=params,
            verify=verify_ssl, timeout=30, max_retries=3
        )

        if response is None or response.status_code != 200:
            # If batched request fails, fall back to per-type queries
            logging.debug(f"    Batched _find failed for space '{space_id}', falling back to per-type queries")
            return _get_object_references_fallback(
                data_view_ids, kibana_url, space_id, object_types, headers, verify_ssl
            )

        data = response.json()
        saved_objects = data.get("saved_objects", [])
        total = data.get("total", 0)

        for obj in saved_objects:
            for ref in obj.get("references", []):
                if ref.get("type") == "index-pattern" and ref.get("id") in data_view_id_set:
                    reference_counts[ref["id"]] += 1

        total_fetched += len(saved_objects)

        # Check if we've retrieved all pages
        if total_fetched >= total or len(saved_objects) == 0:
            break

        page += 1

    return reference_counts


def _get_object_references_fallback(data_view_ids, kibana_url, space_id, object_types, headers, verify_ssl=True):
    """
    Fallback: count references by querying one object type at a time.
    Used when the batched multi-type request fails (e.g., older Kibana versions).
    """
    objects_endpoint = f"{kibana_url}/s/{space_id}/api/saved_objects/_find"
    reference_counts = defaultdict(int)
    data_view_id_set = set(data_view_ids)

    for object_type in object_types:
        params = {
            'fields': 'references',
            'type': object_type,
            'per_page': 10000
        }
        response = _request_with_retry(
            objects_endpoint, headers=headers, params=params,
            verify=verify_ssl, timeout=30, max_retries=2
        )

        if response is None or response.status_code != 200:
            continue

        data = response.json()
        for obj in data.get("saved_objects", []):
            for ref in obj.get("references", []):
                if ref.get("type") == "index-pattern" and ref.get("id") in data_view_id_set:
                    reference_counts[ref["id"]] += 1

    return reference_counts


# ==============================================================================
# CONNECTIVITY CHECK
# ==============================================================================

def check_connectivity(clusters):
    """
    Test connectivity to all configured clusters.

    Args:
        clusters (dict): Cluster configurations

    Returns:
        dict: {cluster_name: True/False}
    """
    results = {}
    for name, cluster in clusters.items():
        if not validate_cluster_config(name, cluster):
            results[name] = False
            continue

        headers = get_headers(cluster["api_key"])
        verify_ssl = cluster.get("verify_ssl", True)
        kibana_url = cluster["kibana_url"]

        try:
            response = requests.get(
                f"{kibana_url}/api/spaces/space",
                headers=headers, verify=verify_ssl, timeout=15
            )
            if response.status_code == 200:
                space_count = len(response.json())
                print(f"  ✅ {name:20s} — Connected ({space_count} spaces)")
                results[name] = True
            else:
                print(f"  ❌ {name:20s} — HTTP {response.status_code}")
                results[name] = False
        except requests.exceptions.RequestException as e:
            print(f"  ❌ {name:20s} — {e}")
            results[name] = False

    return results


# ==============================================================================
# CORE: SCAN A SINGLE CLUSTER
# ==============================================================================

def scan_cluster(name, cluster, object_types, progress_info=None, space_filter=None):
    """
    Scan a single cluster for duplicate data views across all spaces.

    Args:
        name (str): Cluster/deployment name
        cluster (dict): Cluster config dict
        object_types (list): Kibana object types to check references against
        progress_info (dict): Optional dict with 'bar', 'counter', 'lock' for progress tracking
        space_filter (list): Optional list of space IDs or names to include (default: all)

    Returns:
        list: List of result dicts, one per duplicate data view ID found
    """
    kibana_url = cluster["kibana_url"]
    api_key = cluster["api_key"]
    verify_ssl = cluster.get("verify_ssl", True)
    headers = get_headers(api_key)
    results = []

    logging.info(f"[{name}] Scanning {kibana_url} ...")
    spaces = get_all_spaces(headers, kibana_url, verify_ssl)

    if not spaces:
        logging.warning(f"[{name}] No spaces found or unable to connect.")
        # Update progress for this cluster even if it failed
        if progress_info:
            with progress_info["lock"]:
                progress_info["counter"][0] += 1
                progress_info["bar"].update(
                    progress_info["counter"][0],
                    status=f"{name} — no spaces"
                )
        return results

    # Filter spaces if requested
    if space_filter:
        spaces = [s for s in spaces
                  if s.get("id") in space_filter or s.get("name") in space_filter]
        if not spaces:
            logging.warning(f"[{name}] No matching spaces after filter. Skipping.")
            if progress_info:
                with progress_info["lock"]:
                    progress_info["counter"][0] += 1
                    progress_info["bar"].update(
                        progress_info["counter"][0],
                        status=f"{name} — no matching spaces"
                    )
            return results
        logging.info(f"  Filtered to {len(spaces)} space(s)")

    for i, space in enumerate(spaces):
        space_id = space["id"]
        space_name = space.get("name", space_id)

        # Update progress bar with current cluster/space
        if progress_info:
            with progress_info["lock"]:
                progress_info["bar"].update(
                    progress_info["counter"][0],
                    status=f"{name} > {space_name} ({i+1}/{len(spaces)})"
                )

        data_views = get_all_dataviews(space_id, headers, kibana_url, verify_ssl)
        if not data_views:
            continue

        duplicates = find_duplicated_data_views(data_views)
        if not duplicates:
            continue

        # Fetch the default data view ID for this space (one call per space)
        default_dv_id = get_default_dataview_id(space_id, headers, kibana_url, verify_ssl)

        for title, ids in duplicates.items():
            reference_counts = get_object_references(
                ids, kibana_url, space_id, object_types, headers, verify_ssl
            )
            for dv_id in ids:
                results.append({
                    "deployment": name,
                    "kibana_url": kibana_url,
                    "space_id": space_id,
                    "space_name": space_name,
                    "data_view_title": title,
                    "data_view_id": dv_id,
                    "reference_count": reference_counts.get(dv_id, 0),
                    "duplicate_count": len(ids),
                    "is_default": dv_id == default_dv_id if default_dv_id else False,
                })

    # Increment cluster-level progress after finishing all spaces
    if progress_info:
        with progress_info["lock"]:
            progress_info["counter"][0] += 1
            progress_info["bar"].update(
                progress_info["counter"][0],
                status=f"{name} — done ({len(results)} duplicates)"
            )

    return results


# ==============================================================================
# LABELING: KEEP / SAFE TO DELETE
# ==============================================================================

def label_results(all_results):
    """
    Add 'action' labels to each result entry within its duplicate group.

    Logic per duplicate group (same deployment + space + title):
      - Any ID that is the space default         → "KEEP (DEFAULT)"
      - The ID with the highest reference count   → "KEEP"
      - IDs with 0 references and not default     → "SAFE TO DELETE"
      - IDs with >0 references (not the top)      → "REVIEW" (has refs, needs migration)

    Modifies all_results in place.
    """
    # Group by (deployment, space_id, title)
    groups = defaultdict(list)
    for r in all_results:
        key = (r["deployment"], r["space_id"], r["data_view_title"])
        groups[key].append(r)

    for key, entries in groups.items():
        # Sort by reference count descending to find the keep candidate
        entries_sorted = sorted(entries, key=lambda e: e["reference_count"], reverse=True)
        keep_id = entries_sorted[0]["data_view_id"]

        for entry in entries:
            if entry["is_default"]:
                entry["action"] = "KEEP (DEFAULT)"
            elif entry["data_view_id"] == keep_id:
                entry["action"] = "KEEP"
            elif entry["reference_count"] == 0:
                entry["action"] = "SAFE TO DELETE"
            else:
                entry["action"] = "REVIEW"


# ==============================================================================
# OUTPUT / REPORTING
# ==============================================================================

def print_results(all_results, scan_stats=None):
    """Print results grouped by deployment and space, with action labels."""
    if not all_results:
        print("\n" + "=" * 90)
        print("✅ ALL CLEAR: No duplicate data views found across any deployment.")
        print("=" * 90)
        if scan_stats:
            _print_scan_stats(scan_stats)
        return

    # Group results by deployment -> space -> title
    grouped = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for r in all_results:
        grouped[r["deployment"]][r["space_name"]][r["data_view_title"]].append(r)

    total_duplicates = 0
    total_deployments_affected = len(grouped)

    print("\n" + "=" * 90)
    print("DUPLICATE DATA VIEWS REPORT")
    print("=" * 90)

    for deployment in sorted(grouped.keys()):
        spaces = grouped[deployment]
        print(f"\n{'─' * 90}")
        print(f"📦 DEPLOYMENT: {deployment.upper()}")
        print(f"{'─' * 90}")

        for space_name in sorted(spaces.keys()):
            titles = spaces[space_name]
            print(f"\n  🔹 Space: {space_name}")

            for title in sorted(titles.keys()):
                entries = titles[title]
                total_duplicates += 1
                print(f"\n    Data View Title: {title}")
                print(f"    Copies: {entries[0]['duplicate_count']}")

                # Sort: KEEP first, then REVIEW, then SAFE TO DELETE
                action_order = {"KEEP (DEFAULT)": 0, "KEEP": 1, "REVIEW": 2, "SAFE TO DELETE": 3}
                entries_sorted = sorted(entries, key=lambda e: (
                    action_order.get(e.get("action", ""), 99),
                    -e["reference_count"]
                ))

                for entry in entries_sorted:
                    ref_count = entry['reference_count']
                    ref_label = f"{ref_count} refs"
                    action = entry.get("action", "")

                    # Build the action tag
                    if action == "KEEP (DEFAULT)":
                        tag = "  ← KEEP (DEFAULT)"
                    elif action == "KEEP":
                        tag = "  ← KEEP"
                    elif action == "SAFE TO DELETE":
                        tag = "  ← SAFE TO DELETE"
                    elif action == "REVIEW":
                        tag = "  ← REVIEW (has refs)"
                    else:
                        tag = ""

                    print(f"      ID: {entry['data_view_id']:45s}  ({ref_label}){tag}")

    # Summary
    total_entries = len(all_results)
    safe_to_delete = sum(1 for r in all_results if r.get("action") == "SAFE TO DELETE")
    review_count = sum(1 for r in all_results if r.get("action") == "REVIEW")

    print(f"\n{'=' * 90}")
    print("SUMMARY")
    print(f"{'=' * 90}")
    print(f"  Deployments with duplicates : {total_deployments_affected}")
    print(f"  Duplicate title groups       : {total_duplicates}")
    print(f"  Total duplicate data view IDs: {total_entries}")
    print(f"  Safe to delete (0 refs)      : {safe_to_delete}")
    print(f"  Needs review (has refs)      : {review_count}")

    if scan_stats:
        _print_scan_stats(scan_stats)
    else:
        print(f"{'=' * 90}")


def _print_scan_stats(scan_stats):
    """Print scan statistics (clusters scanned, elapsed time, etc.)."""
    print(f"{'─' * 90}")
    total = scan_stats.get("total", 0)
    clean = scan_stats.get("clean", 0)
    with_dups = scan_stats.get("with_duplicates", 0)
    failed = scan_stats.get("failed", 0)
    elapsed = scan_stats.get("elapsed", 0)
    incomplete = scan_stats.get("incomplete", 0)
    interrupted = scan_stats.get("interrupted", False)

    status_parts = [
        f"Clusters scanned: {total}",
        f"Clean: {clean}",
        f"With duplicates: {with_dups}",
        f"Failed: {failed}",
    ]
    if interrupted:
        status_parts.append(f"Incomplete: {incomplete}")
    print(f"  {'  |  '.join(status_parts)}")

    if interrupted:
        print(f"  ⚠️  Scan was interrupted — results above are PARTIAL")

    if elapsed >= 3600:
        h, remainder = divmod(int(elapsed), 3600)
        m, s = divmod(remainder, 60)
        print(f"  Total scan time: {h}h {m}m {s}s")
    elif elapsed >= 60:
        m, s = divmod(int(elapsed), 60)
        print(f"  Total scan time: {m}m {s}s")
    else:
        print(f"  Total scan time: {elapsed:.1f}s")
    print(f"{'=' * 90}")


# ==============================================================================
# DRY-RUN DELETE PREVIEW
# ==============================================================================

def print_dry_run_delete(all_results):
    """
    Print a preview of which data views would be deleted in an auto-delete run.
    Only zero-reference, non-default data views labeled SAFE TO DELETE are shown.
    """
    candidates = [r for r in all_results if r.get("action") == "SAFE TO DELETE"]

    print(f"\n{'=' * 90}")
    print("DRY-RUN DELETE PREVIEW")
    print("The following data views have 0 references and are NOT the space default.")
    print("These would be deleted in an auto-delete run.")
    print(f"{'=' * 90}")

    if not candidates:
        print("\n  ✅ No orphaned duplicates found — nothing to delete.")
        print(f"{'=' * 90}")
        return

    # Group by deployment -> space
    grouped = defaultdict(lambda: defaultdict(list))
    for c in candidates:
        grouped[c["deployment"]][c["space_name"]].append(c)

    total = 0
    for deployment in sorted(grouped.keys()):
        spaces = grouped[deployment]
        print(f"\n  📦 {deployment.upper()}")

        for space_name in sorted(spaces.keys()):
            entries = spaces[space_name]
            print(f"    🔹 {space_name}")
            for entry in sorted(entries, key=lambda e: e["data_view_title"]):
                total += 1
                print(f"      DELETE  {entry['data_view_id']:45s}  (title: {entry['data_view_title']})")
                # Show the Kibana API call that would be used
                dv_url = f"{entry['kibana_url']}/s/{entry['space_id']}/api/data_views/data_view/{entry['data_view_id']}"
                print(f"              → DELETE {dv_url}")

    print(f"\n{'─' * 90}")
    print(f"  Total data views that would be deleted: {total}")
    print(f"  ⚠️  This is a PREVIEW only — no changes were made.")
    print(f"{'=' * 90}")


# ==============================================================================
# TOP OFFENDERS
# ==============================================================================

def print_top_offenders(all_results, top_n=15):
    """
    Print a ranking of spaces with the most duplicate data view IDs.
    Shows deployment, space, number of duplicate groups, and total duplicate IDs.
    """
    if not all_results:
        return

    # Count per (deployment, space)
    space_stats = defaultdict(lambda: {"groups": set(), "ids": 0, "safe_to_delete": 0})
    for r in all_results:
        key = (r["deployment"], r["space_name"])
        space_stats[key]["groups"].add(r["data_view_title"])
        space_stats[key]["ids"] += 1
        if r.get("action") == "SAFE TO DELETE":
            space_stats[key]["safe_to_delete"] += 1

    # Sort by total duplicate IDs descending
    ranked = sorted(space_stats.items(), key=lambda x: x[1]["ids"], reverse=True)

    print(f"\n{'=' * 90}")
    print(f"TOP OFFENDERS — Spaces with the most duplicate data views")
    print(f"{'=' * 90}")
    print(f"  {'#':<4} {'Deployment':<30} {'Space':<28} {'Groups':>7} {'IDs':>6} {'Deletable':>10}")
    print(f"  {'─' * 86}")

    for i, (key, stats) in enumerate(ranked[:top_n]):
        deployment, space_name = key
        groups = len(stats["groups"])
        ids = stats["ids"]
        deletable = stats["safe_to_delete"]
        print(f"  {i+1:<4} {deployment:<30} {space_name:<28} {groups:>7} {ids:>6} {deletable:>10}")

    if len(ranked) > top_n:
        print(f"  ... and {len(ranked) - top_n} more spaces with duplicates")
    print(f"{'=' * 90}")


# ==============================================================================
# EXPORT
# ==============================================================================

def export_csv(all_results, output_file):
    """Export results to CSV file."""
    if not all_results:
        print("No results to export.")
        return

    fieldnames = [
        "deployment", "space_id", "space_name", "data_view_title",
        "data_view_id", "reference_count", "duplicate_count",
        "is_default", "action"
    ]
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(all_results)
    print(f"\n📄 CSV report exported to: {output_file}")


def export_json(all_results, output_file):
    """Export results to JSON file."""
    if not all_results:
        print("No results to export.")
        return

    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\n📄 JSON report exported to: {output_file}")


# ==============================================================================
# LOGGING SETUP
# ==============================================================================

def setup_logging(verbose=False, log_file=None):
    """
    Configure logging to stdout and optionally to a file.

    Args:
        verbose (bool): Enable DEBUG level logging
        log_file (str): Optional path to a log file. If 'auto', a timestamped
                        filename is generated. Logs go to both stdout and file.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s - %(levelname)s - %(message)s"

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        # Auto-generate filename with timestamp if 'auto'
        if log_file == "auto":
            log_file = f"duplicate_dataviews_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)

    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=handlers,
    )

    if log_file:
        logging.info(f"Logging to file: {log_file}")


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    parser = ArgumentParser(
        description='Find duplicate data views across multiple Kibana deployments.'
    )
    parser.add_argument(
        '--config', default='clusters.json',
        help='Path to the clusters JSON config file (default: clusters.json)'
    )
    parser.add_argument(
        '--clusters', nargs='+', default=None,
        help='Specific cluster names to scan (default: scan all)'
    )
    parser.add_argument(
        '--spaces', nargs='+', default=None,
        help='Specific space IDs or names to scan (default: scan all spaces)'
    )
    parser.add_argument(
        '--output', choices=['table', 'csv', 'json'], default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '--output-file', default=None,
        help='Output file path for csv/json (auto-generated if not specified)'
    )
    parser.add_argument(
        '--connectivity-check', action='store_true',
        help='Only test connectivity to all clusters, then exit'
    )
    parser.add_argument(
        '--workers', type=int, default=1,
        help='Number of concurrent workers for scanning clusters (default: 1)'
    )
    parser.add_argument(
        '--verbose', action='store_true',
        help='Enable verbose/debug logging'
    )
    parser.add_argument(
        '--dry-run-delete', action='store_true',
        help='Preview which orphaned data views (0 refs, not default) would be deleted'
    )
    parser.add_argument(
        '--top-offenders', action='store_true',
        help='Show a ranking of spaces with the most duplicate data views'
    )
    parser.add_argument(
        '--log-file', nargs='?', const='auto', default=None,
        help='Write logs to a file. Optionally specify a path (default: auto-timestamped)'
    )

    args = parser.parse_args()

    # Setup logging (with optional file output)
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Load config
    config = load_config(args.config)
    clusters = config["clusters"]

    # Filter to specific clusters if requested
    if args.clusters:
        filtered = {}
        for c in args.clusters:
            if c in clusters:
                filtered[c] = clusters[c]
            else:
                logging.warning(f"Cluster '{c}' not found in config. Available: {list(clusters.keys())}")
        clusters = filtered
        if not clusters:
            logging.error("No valid clusters to scan.")
            sys.exit(1)

    # Connectivity check mode
    if args.connectivity_check:
        print("\n🔌 CONNECTIVITY CHECK")
        print("=" * 60)
        results = check_connectivity(clusters)
        success = sum(1 for v in results.values() if v)
        total = len(results)
        print(f"\n  Result: {success}/{total} clusters reachable")
        sys.exit(0 if success == total else 1)

    # Validate all clusters before starting
    valid_clusters = {}
    for name, cluster in clusters.items():
        if validate_cluster_config(name, cluster):
            valid_clusters[name] = cluster

    if not valid_clusters:
        logging.error("No valid clusters to scan after validation.")
        sys.exit(1)

    object_types = get_object_types()
    all_results = []
    cluster_results = {}  # track per-cluster result counts for stats

    print(f"\n🔍 Scanning {len(valid_clusters)} deployment(s) for duplicate data views...\n")
    start_time = time.time()

    # Set up progress bar and thread-safe counter
    import threading
    progress_bar = ProgressBar(total=len(valid_clusters), prefix="Clusters")
    progress_counter = [0]  # mutable list so threads can update it
    progress_lock = threading.Lock()
    progress_info = {
        "bar": progress_bar,
        "counter": progress_counter,
        "lock": progress_lock,
    }

    failed_clusters = []
    interrupted = False

    # Sequential or concurrent execution — wrapped in KeyboardInterrupt handler
    # so Ctrl+C prints partial results instead of a raw traceback
    try:
        if args.workers > 1 and len(valid_clusters) > 1:
            logging.info(f"Using {args.workers} concurrent workers")
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(scan_cluster, name, cluster, object_types, progress_info, args.spaces): name
                    for name, cluster in valid_clusters.items()
                }
                for future in as_completed(futures):
                    cluster_name = futures[future]
                    try:
                        results = future.result()
                        all_results.extend(results)
                        cluster_results[cluster_name] = len(results)
                    except Exception as e:
                        logging.error(f"[{cluster_name}] Scan failed: {e}")
                        failed_clusters.append(cluster_name)
                        with progress_lock:
                            progress_counter[0] += 1
                            progress_bar.update(progress_counter[0], status=f"{cluster_name} — FAILED")
        else:
            for name, cluster in valid_clusters.items():
                try:
                    results = scan_cluster(name, cluster, object_types, progress_info, args.spaces)
                    all_results.extend(results)
                    cluster_results[name] = len(results)
                except Exception as e:
                    logging.error(f"[{name}] Scan failed: {e}")
                    failed_clusters.append(name)
                    with progress_lock:
                        progress_counter[0] += 1
                        progress_bar.update(progress_counter[0], status=f"{name} — FAILED")

    except KeyboardInterrupt:
        interrupted = True
        elapsed = time.time() - start_time
        # Clear the progress bar line and print the interrupt message
        sys.stdout.write("\n")
        sys.stdout.flush()
        print(f"\n{'!' * 90}")
        print(f"⚠️  INTERRUPTED — Scan stopped after {elapsed:.1f}s")
        print(f"   Completed {progress_counter[0]}/{len(valid_clusters)} clusters before interruption.")
        print(f"   Partial results ({len(all_results)} duplicate entries) will be printed below.")
        print(f"{'!' * 90}")

    elapsed = time.time() - start_time

    if not interrupted:
        progress_bar.finish(summary=f"{len(all_results)} duplicate entries found")

    # Build scan stats for the summary
    completed_clusters = len(cluster_results)
    with_dups = sum(1 for c, count in cluster_results.items() if count > 0)
    clean = sum(1 for c, count in cluster_results.items() if count == 0)
    # If interrupted, clusters that never started are counted as incomplete (not failed)
    incomplete = len(valid_clusters) - completed_clusters - len(failed_clusters)
    scan_stats = {
        "total": len(valid_clusters),
        "clean": clean,
        "with_duplicates": with_dups,
        "failed": len(failed_clusters),
        "elapsed": elapsed,
    }
    if interrupted:
        scan_stats["interrupted"] = True
        scan_stats["incomplete"] = incomplete

    logging.info(f"Scan completed in {elapsed:.1f} seconds")

    # Label results with KEEP / SAFE TO DELETE / REVIEW
    label_results(all_results)

    # Output results
    if args.output == 'table' or args.output == 'csv':
        print_results(all_results, scan_stats=scan_stats)

    if args.output == 'csv':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = args.output_file or f"duplicate_dataviews_{timestamp}.csv"
        export_csv(all_results, output_file)

    if args.output == 'json':
        print_results(all_results, scan_stats=scan_stats)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = args.output_file or f"duplicate_dataviews_{timestamp}.json"
        export_json(all_results, output_file)

    # Dry-run delete preview
    if args.dry_run_delete:
        print_dry_run_delete(all_results)

    # Top offenders ranking
    if args.top_offenders:
        print_top_offenders(all_results)


if __name__ == "__main__":
    main()
