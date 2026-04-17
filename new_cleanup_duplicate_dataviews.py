#!/usr/bin/env python3
"""
Cleanup Duplicate Data Views Across Multiple Kibana Deployments

This script safely removes duplicate data views across Kibana deployments by:
  1. Scanning for duplicates (using the same engine as find_duplicate_dataviews.py)
  2. Identifying the KEEP candidate (highest reference count or default)
  3. Re-pointing all saved-object references from duplicates → KEEP candidate
  4. Presenting a validation report for user approval before any deletion
  5. Backing up each data view before deletion
  6. Deleting only confirmed orphaned duplicates (0 references, not default)

Safety features:
  - Full NDJSON backup of all space objects before any changes
  - Per-data-view NDJSON backup before deletion
  - Interactive validation prompt before deletions
  - Dry-run mode (default) — no changes made unless --execute is passed
  - Comprehensive audit log file
  - Default data view detection — never deletes the space default
  - Reference re-pointing — migrates refs before deletion so nothing breaks

Usage:
    # Dry-run (default) — preview what would happen, no changes made
    python cleanup_duplicate_dataviews.py

    # Dry-run for a specific cluster and space
    python cleanup_duplicate_dataviews.py \
        --clusters "FISMA Scorecard" --spaces "FISMA Team"

    # Execute with interactive validation
    python cleanup_duplicate_dataviews.py --execute

    # Execute and auto-confirm all deletions (no prompts)
    python cleanup_duplicate_dataviews.py --execute --yes

    # Use a custom config file
    python cleanup_duplicate_dataviews.py --config /path/to/my_clusters.json

    # Custom log file path
    python cleanup_duplicate_dataviews.py --log-file cleanup.log
"""

import sys
import os
import requests
import logging
import json
import time
from collections import defaultdict
from argparse import ArgumentParser
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==============================================================================
# LOGGING
# ==============================================================================

def setup_logging(log_file=None, verbose=False):
    """Configure logging to stdout and optionally to a file."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        if log_file == "auto":
            log_file = f"cleanup_dataviews_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)

    logging.basicConfig(level=log_level, format=log_format, handlers=handlers)

    if log_file:
        logging.info(f"Audit log: {log_file}")
    return log_file


# ==============================================================================
# CONFIGURATION (same as find_duplicate_dataviews.py)
# ==============================================================================

def load_config(config_path):
    """Load and resolve cluster configuration from JSON file."""
    if not os.path.exists(config_path):
        logging.error(f"Config file not found: {config_path}")
        sys.exit(1)
    with open(config_path, 'r') as f:
        config = json.load(f)
    clusters = config.get("clusters", {})
    if not clusters:
        logging.error("No clusters defined in config file.")
        sys.exit(1)
    for name, cluster in clusters.items():
        api_key = cluster.get("api_key", "")
        if api_key.startswith("$"):
            env_var = api_key[1:]
            resolved = os.environ.get(env_var)
            cluster["api_key"] = resolved if resolved else None
            if not resolved:
                logging.warning(f"[{name}] Env var '{env_var}' not set.")
        if "verify_ssl" not in cluster:
            cluster["verify_ssl"] = True
        if "kibana_url" in cluster:
            cluster["kibana_url"] = cluster["kibana_url"].rstrip("/")
    return config


def get_headers(api_key):
    return {
        'kbn-xsrf': 'true',
        'Content-Type': 'application/json',
        'Authorization': f'ApiKey {api_key}'
    }


def get_object_types():
    return [
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


# ==============================================================================
# KIBANA API HELPERS (with retry logic)
# ==============================================================================

def _request_with_retry(method, url, headers, params=None, json_body=None,
                        verify=True, timeout=30, max_retries=3):
    """Make an HTTP request with retry logic and exponential backoff."""
    for attempt in range(max_retries):
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, params=params,
                                        verify=verify, timeout=timeout)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=json_body,
                                        verify=verify, timeout=timeout)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=json_body,
                                         verify=verify, timeout=timeout)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers,
                                           verify=verify, timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")

            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            wait = 2 ** attempt
            logging.warning(f"  Timeout ({attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.ConnectionError:
            wait = 2 ** attempt
            logging.warning(f"  Connection error ({attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.HTTPError as e:
            if response is not None and 400 <= response.status_code < 500 and response.status_code != 429:
                return response
            wait = 2 ** attempt
            logging.warning(f"  HTTP {response.status_code} ({attempt+1}/{max_retries}), retrying in {wait}s...")
            time.sleep(wait)
        except requests.exceptions.RequestException as e:
            logging.error(f"  Request failed: {e}")
            return None
    logging.error(f"  All {max_retries} retries exhausted for {url}")
    return None


def get_all_spaces(headers, kibana_url, verify_ssl=True):
    """Retrieve all Kibana spaces."""
    response = _request_with_retry("GET", f"{kibana_url}/api/spaces/space",
                                   headers, verify=verify_ssl)
    if response and response.status_code == 200:
        return response.json()
    return []


def get_all_dataviews(space_id, headers, kibana_url, verify_ssl=True):
    """Get all data views in a space."""
    url = f'{kibana_url}/s/{space_id}/api/data_views'
    response = _request_with_retry("GET", url, headers, verify=verify_ssl)
    if response and response.status_code == 200:
        return response.json().get('data_view', [])
    return []


def get_default_dataview_id(space_id, headers, kibana_url, verify_ssl=True):
    """Get the default data view ID for a space."""
    url = f'{kibana_url}/s/{space_id}/api/data_views/default'
    try:
        response = requests.get(url, headers=headers, verify=verify_ssl, timeout=15)
        if response.status_code == 200:
            return response.json().get("data_view_id") or None
    except requests.exceptions.RequestException:
        pass
    return None


def find_duplicated_data_views(data_views):
    """Find data views with duplicate titles."""
    title_to_ids = defaultdict(list)
    for dv in data_views:
        title = dv.get("title")
        if not title:
            continue
        title_to_ids[title].append(dv["id"])
    return {title: ids for title, ids in title_to_ids.items() if len(ids) > 1}


def get_all_saved_objects(kibana_url, space_id, headers, object_types, verify_ssl=True):
    """
    Retrieve ALL saved objects in a space with their references.
    Uses batched multi-type API call for performance.
    Returns list of saved object dicts.
    """
    endpoint = f"{kibana_url}/s/{space_id}/api/saved_objects/_find"
    base_params = [('fields', 'references'), ('per_page', '10000')]
    for ot in object_types:
        base_params.append(('type', ot))

    all_objects = []
    page = 1
    while True:
        params = base_params + [('page', str(page))]
        response = _request_with_retry("GET", endpoint, headers, params=params,
                                       verify=verify_ssl)
        if response is None or response.status_code != 200:
            logging.warning(f"  Failed to retrieve saved objects for space '{space_id}'")
            break

        data = response.json()
        objects = data.get("saved_objects", [])
        all_objects.extend(objects)
        total = data.get("total", 0)
        if len(all_objects) >= total or not objects:
            break
        page += 1

    return all_objects


def count_references(data_view_ids, all_objects):
    """Count references to each data view ID from saved objects."""
    counts = defaultdict(int)
    dv_set = set(data_view_ids)
    for obj in all_objects:
        for ref in obj.get("references", []):
            if ref.get("type") == "index-pattern" and ref.get("id") in dv_set:
                counts[ref["id"]] += 1
    return counts


# ==============================================================================
# BACKUP FUNCTIONS
# ==============================================================================

def backup_space_objects(kibana_url, space_id, headers, all_kibana_objects, verify_ssl=True, backup_dir="backups"):
    """
    Export all Kibana objects in a space to an NDJSON backup file.
    Returns the backup file path or None on failure.
    """
    os.makedirs(backup_dir, exist_ok=True)
    export_url = f"{kibana_url}/s/{space_id}/api/saved_objects/_export"

    # Build the objects list for export
    export_objects = [{"id": obj["id"], "type": obj["type"]} for obj in all_kibana_objects]
    if not export_objects:
        logging.info(f"  No objects to backup in space '{space_id}'")
        return None

    payload = {"objects": export_objects, "includeReferencesDeep": True}
    response = _request_with_retry("POST", export_url, headers, json_body=payload,
                                   verify=verify_ssl, timeout=60)

    if response and response.status_code == 200:
        safe_space = space_id.replace("/", "_").replace(" ", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"space_{safe_space}_{ts}.ndjson")
        with open(backup_file, "w") as f:
            f.write(response.text)
        logging.info(f"  ✅ Space backup saved: {backup_file} ({len(export_objects)} objects)")
        return backup_file
    else:
        logging.error(f"  ❌ Failed to backup space '{space_id}'")
        return None


def backup_data_view(kibana_url, space_id, headers, data_view_id, verify_ssl=True, backup_dir="backups"):
    """Backup a single data view to NDJSON before deletion."""
    os.makedirs(backup_dir, exist_ok=True)
    export_url = f"{kibana_url}/s/{space_id}/api/saved_objects/_export"
    payload = {
        "objects": [{"id": data_view_id, "type": "index-pattern"}],
        "includeReferencesDeep": True
    }
    response = _request_with_retry("POST", export_url, headers, json_body=payload,
                                   verify=verify_ssl, timeout=30)
    if response and response.status_code == 200:
        safe_id = data_view_id.replace("/", "_")
        backup_file = os.path.join(backup_dir, f"dataview_{safe_id}.ndjson")
        with open(backup_file, "w") as f:
            f.write(response.text)
        logging.info(f"    Backup: {backup_file}")
        return backup_file
    logging.warning(f"    ⚠️ Could not backup data view {data_view_id}")
    return None


# ==============================================================================
# REFERENCE RE-POINTING
# ==============================================================================

def repoint_references(all_objects, old_id, new_id, kibana_url, space_id, headers,
                       verify_ssl=True, dry_run=True):
    """
    Update all saved objects that reference old_id to point to new_id.
    Returns the count of objects updated.
    """
    updated_count = 0
    for obj in all_objects:
        refs = obj.get("references", [])
        needs_update = False
        new_refs = []
        for ref in refs:
            if ref.get("type") == "index-pattern" and ref.get("id") == old_id:
                new_ref = ref.copy()
                new_ref["id"] = new_id
                new_refs.append(new_ref)
                needs_update = True
            else:
                new_refs.append(ref)

        if needs_update:
            obj_id = obj["id"]
            obj_type = obj["type"]
            if dry_run:
                logging.info(f"    [DRY-RUN] Would repoint {obj_type}/{obj_id}: {old_id} → {new_id}")
            else:
                endpoint = f"{kibana_url}/s/{space_id}/api/saved_objects/{obj_type}/{obj_id}"
                payload = {"attributes": {}, "references": new_refs}
                resp = _request_with_retry("PUT", endpoint, headers, json_body=payload,
                                           verify=verify_ssl)
                if resp and resp.status_code == 200:
                    logging.info(f"    ✅ Repointed {obj_type}/{obj_id}: {old_id} → {new_id}")
                    # Update the in-memory object so subsequent checks see the new refs
                    obj["references"] = new_refs
                else:
                    status = resp.status_code if resp else "no response"
                    logging.error(f"    ❌ Failed to repoint {obj_type}/{obj_id}: HTTP {status}")
            updated_count += 1
    return updated_count


# ==============================================================================
# DELETION
# ==============================================================================

def delete_data_view(kibana_url, space_id, headers, data_view_id, verify_ssl=True):
    """Delete a data view by ID. Returns True on success."""
    url = f"{kibana_url}/s/{space_id}/api/data_views/data_view/{data_view_id}"
    response = _request_with_retry("DELETE", url, headers, verify=verify_ssl)
    if response and response.status_code == 200:
        logging.info(f"    ✅ DELETED data view: {data_view_id}")
        return True
    else:
        status = response.status_code if response else "no response"
        logging.error(f"    ❌ Failed to delete {data_view_id}: HTTP {status}")
        return False


# ==============================================================================
# VALIDATION / INTERACTIVE APPROVAL
# ==============================================================================

def present_cleanup_plan(plan, dry_run=True):
    """
    Present the cleanup plan to the user for validation.
    Returns the (possibly filtered) list of data views approved for deletion.
    """
    mode = "DRY-RUN" if dry_run else "EXECUTE"
    print(f"\n{'=' * 90}")
    print(f"CLEANUP PLAN — [{mode}]")
    print(f"{'=' * 90}")

    if not plan:
        print("\n  ✅ Nothing to clean up — no deletable duplicates found.")
        print(f"{'=' * 90}")
        return []

    total_repoints = 0
    total_deletions = 0

    for item in plan:
        print(f"\n  📦 {item['deployment'].upper()} > {item['space_name']}")
        print(f"    Data View Title: {item['title']}")
        print(f"    KEEP:   {item['keep_id']:45s}  ({item['keep_refs']} refs)"
              + (" ← DEFAULT" if item.get('keep_is_default') else ""))

        for dup in item['duplicates']:
            action = dup['action']
            if action == "REPOINT + DELETE":
                print(f"    DELETE: {dup['id']:45s}  ({dup['refs']} refs → repoint to KEEP, then delete)")
                total_repoints += dup['refs']
            elif action == "DELETE":
                print(f"    DELETE: {dup['id']:45s}  (0 refs → delete)")
            elif action == "SKIP (DEFAULT)":
                print(f"    SKIP:   {dup['id']:45s}  ({dup['refs']} refs — is space DEFAULT)")
            total_deletions += 1 if action in ("DELETE", "REPOINT + DELETE") else 0

    print(f"\n{'─' * 90}")
    print(f"  Total reference re-points : {total_repoints}")
    print(f"  Total data views to delete: {total_deletions}")
    print(f"{'=' * 90}")

    return plan


def get_user_approval(plan, auto_yes=False):
    """
    Prompt user for approval. Returns list of approved plan items.
    In auto_yes mode, all items are approved without prompting.
    """
    if auto_yes:
        logging.info("Auto-confirm enabled (--yes): all deletions approved.")
        return plan

    deletable = [item for item in plan
                 if any(d['action'] in ("DELETE", "REPOINT + DELETE") for d in item['duplicates'])]

    if not deletable:
        return []

    print(f"\n⚠️  You are about to modify {len(deletable)} duplicate group(s).")
    approval = input("  Proceed with cleanup? [y/N/item-by-item]: ").strip().lower()

    if approval == 'y':
        logging.info("User approved ALL deletions.")
        return deletable
    elif approval == 'item-by-item':
        approved = []
        for item in deletable:
            desc = f"{item['deployment']} > {item['space_name']} > {item['title']}"
            choice = input(f"  Delete duplicates for '{desc}'? [y/N]: ").strip().lower()
            if choice == 'y':
                approved.append(item)
                logging.info(f"User approved: {desc}")
            else:
                logging.info(f"User skipped: {desc}")
        return approved
    else:
        logging.info("User declined all deletions. No changes made.")
        return []


# ==============================================================================
# CORE: PROCESS ONE SPACE
# ==============================================================================

def process_space(deployment_name, kibana_url, space_id, space_name, headers,
                  object_types, verify_ssl, dry_run, auto_yes, backup_dir):
    """
    Scan one space for duplicates, build cleanup plan, execute if approved.
    Returns dict with stats.
    """
    stats = {"repointed": 0, "deleted": 0, "skipped": 0, "backed_up": 0, "errors": 0}
    logging.info(f"[{deployment_name}] Processing space: {space_name} ({space_id})")

    # 1. Get all data views
    data_views = get_all_dataviews(space_id, headers, kibana_url, verify_ssl)
    if not data_views:
        logging.info(f"  No data views in space '{space_name}'. Skipping.")
        return stats

    # 2. Find duplicates
    duplicates = find_duplicated_data_views(data_views)
    if not duplicates:
        logging.info(f"  No duplicates in space '{space_name}'. Skipping.")
        return stats

    logging.info(f"  Found {len(duplicates)} duplicate group(s) in '{space_name}'")

    # 3. Get all saved objects (batched, one call)
    all_objects = get_all_saved_objects(kibana_url, space_id, headers, object_types, verify_ssl)
    logging.info(f"  Loaded {len(all_objects)} saved objects for reference analysis")

    # 4. Get default data view
    default_dv_id = get_default_dataview_id(space_id, headers, kibana_url, verify_ssl)

    # 5. Build cleanup plan for this space
    space_plan = []
    for title, ids in duplicates.items():
        ref_counts = count_references(ids, all_objects)

        # Determine KEEP candidate: default > highest refs > first
        keep_id = None
        if default_dv_id in ids:
            keep_id = default_dv_id
        else:
            keep_id = max(ids, key=lambda x: ref_counts.get(x, 0))

        plan_item = {
            "deployment": deployment_name,
            "kibana_url": kibana_url,
            "space_id": space_id,
            "space_name": space_name,
            "title": title,
            "keep_id": keep_id,
            "keep_refs": ref_counts.get(keep_id, 0),
            "keep_is_default": keep_id == default_dv_id,
            "duplicates": []
        }

        for dv_id in ids:
            if dv_id == keep_id:
                continue  # This is the one we keep
            refs = ref_counts.get(dv_id, 0)
            is_default = dv_id == default_dv_id

            if is_default:
                action = "SKIP (DEFAULT)"
            elif refs > 0:
                action = "REPOINT + DELETE"
            else:
                action = "DELETE"

            plan_item["duplicates"].append({
                "id": dv_id, "refs": refs, "is_default": is_default, "action": action
            })

        space_plan.append(plan_item)

    # 6. Present plan and get approval
    present_cleanup_plan(space_plan, dry_run=dry_run)

    if dry_run:
        logging.info("  [DRY-RUN] No changes made. Re-run with --execute to apply.")
        return stats

    approved = get_user_approval(space_plan, auto_yes=auto_yes)
    if not approved:
        logging.info("  No items approved. Skipping space.")
        return stats

    # 7. Backup entire space before making changes
    logging.info(f"  Backing up all objects in space '{space_name}'...")
    backup_space_objects(kibana_url, space_id, headers, all_objects, verify_ssl, backup_dir)
    stats["backed_up"] += 1

    # 8. Execute: repoint references, then delete
    for item in approved:
        keep_id = item["keep_id"]
        for dup in item["duplicates"]:
            dv_id = dup["id"]
            action = dup["action"]

            if action == "SKIP (DEFAULT)":
                stats["skipped"] += 1
                continue

            # Repoint references if needed
            if action == "REPOINT + DELETE":
                logging.info(f"  Re-pointing {dup['refs']} references: {dv_id} → {keep_id}")
                count = repoint_references(all_objects, dv_id, keep_id,
                                           kibana_url, space_id, headers, verify_ssl,
                                           dry_run=False)
                stats["repointed"] += count

            # Backup the individual data view
            backup_data_view(kibana_url, space_id, headers, dv_id, verify_ssl, backup_dir)

            # Verify no remaining references before deleting
            fresh_refs = count_references([dv_id], all_objects)
            remaining = fresh_refs.get(dv_id, 0)
            if remaining > 0:
                logging.error(f"    ⚠️ {dv_id} still has {remaining} references after repoint! Skipping delete.")
                stats["errors"] += 1
                continue

            # Delete
            success = delete_data_view(kibana_url, space_id, headers, dv_id, verify_ssl)
            if success:
                stats["deleted"] += 1
            else:
                stats["errors"] += 1

    return stats


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    parser = ArgumentParser(
        description='Safely clean up duplicate data views across Kibana deployments.'
    )
    parser.add_argument('--config', default='clusters.json',
                        help='Path to clusters.json config file (default: clusters.json)')
    parser.add_argument('--clusters', nargs='+', default=None,
                        help='Specific cluster names to process (default: all)')
    parser.add_argument('--spaces', nargs='+', default=None,
                        help='Specific space IDs or names to process (default: all)')
    parser.add_argument('--execute', action='store_true',
                        help='Actually perform changes (default is dry-run)')
    parser.add_argument('--yes', action='store_true',
                        help='Auto-confirm all deletions (skip interactive prompts)')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--log-file', nargs='?', const='auto', default='auto',
                        help='Write audit log to file (default: auto-timestamped)')
    parser.add_argument('--backup-dir', default='backups',
                        help='Directory for NDJSON backups (default: ./backups)')

    args = parser.parse_args()
    dry_run = not args.execute

    # Setup logging
    log_file = setup_logging(log_file=args.log_file, verbose=args.verbose)

    if dry_run:
        print("\n" + "=" * 90)
        print("🔒 DRY-RUN MODE — No changes will be made. Use --execute to apply changes.")
        print("=" * 90)
    else:
        print("\n" + "=" * 90)
        print("⚠️  EXECUTE MODE — Changes WILL be applied to your Kibana deployments!")
        print("=" * 90)

    # Load config
    config = load_config(args.config)
    clusters = config["clusters"]

    # Filter clusters
    if args.clusters:
        filtered = {k: v for k, v in clusters.items() if k in args.clusters}
        if not filtered:
            logging.error(f"No matching clusters. Available: {list(clusters.keys())}")
            sys.exit(1)
        clusters = filtered

    object_types = get_object_types()
    total_stats = {"repointed": 0, "deleted": 0, "skipped": 0, "backed_up": 0, "errors": 0}
    start_time = time.time()

    for cluster_name, cluster in clusters.items():
        if not cluster.get("api_key"):
            logging.warning(f"[{cluster_name}] No API key. Skipping.")
            continue

        kibana_url = cluster["kibana_url"]
        headers = get_headers(cluster["api_key"])
        verify_ssl = cluster.get("verify_ssl", True)

        logging.info(f"[{cluster_name}] Scanning {kibana_url} ...")
        spaces = get_all_spaces(headers, kibana_url, verify_ssl)

        if not spaces:
            logging.warning(f"[{cluster_name}] No spaces found. Skipping.")
            continue

        logging.info(f"[{cluster_name}] Found {len(spaces)} spaces")

        # Filter spaces if requested
        if args.spaces:
            spaces = [s for s in spaces
                      if s.get("id") in args.spaces or s.get("name") in args.spaces]
            if not spaces:
                logging.warning(f"[{cluster_name}] No matching spaces after filter.")
                continue

        for space in spaces:
            space_id = space["id"]
            space_name = space.get("name", space_id)

            try:
                stats = process_space(
                    cluster_name, kibana_url, space_id, space_name,
                    headers, object_types, verify_ssl,
                    dry_run, args.yes, args.backup_dir
                )
                for k in total_stats:
                    total_stats[k] += stats[k]
            except Exception as e:
                logging.error(f"[{cluster_name}] Error processing space '{space_name}': {e}")
                total_stats["errors"] += 1

    elapsed = time.time() - start_time

    # Final summary
    print(f"\n{'=' * 90}")
    print(f"CLEANUP {'DRY-RUN ' if dry_run else ''}SUMMARY")
    print(f"{'=' * 90}")
    print(f"  References re-pointed : {total_stats['repointed']}")
    print(f"  Data views deleted    : {total_stats['deleted']}")
    print(f"  Skipped (default/safe): {total_stats['skipped']}")
    print(f"  Spaces backed up      : {total_stats['backed_up']}")
    print(f"  Errors                : {total_stats['errors']}")
    print(f"  Total time            : {elapsed:.1f}s")
    if log_file:
        print(f"  Audit log             : {log_file}")
    print(f"{'=' * 90}")


if __name__ == "__main__":
    main()
