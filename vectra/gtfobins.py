import re
import zipfile
import sqlite3
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
from pathlib import Path

def _get_config():
    from vectra.config import GTFOBINS_REPO_ZIP, DEFAULT_DATA_DIR
    return GTFOBINS_REPO_ZIP, DEFAULT_DATA_DIR

def _get_db():
    from vectra.db import get_db_connection, init_db, save_gtfobins_batch, set_metadata, get_metadata
    return get_db_connection, init_db, save_gtfobins_batch, set_metadata, get_metadata

def check_gtfobins_updates(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Check if GTFOBins has been updated upstream using HTTP ETag/Last-Modified headers.
    
    Returns a dict with: has_updates, current_etag, remote_etag, last_sync, error
    """
    GTFOBINS_REPO_ZIP, _ = _get_config()
    get_db_connection, _, _, set_metadata, get_metadata = _get_db()

    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    current_etag = get_metadata(conn, "gtfobins_etag") or ""
    last_sync = get_metadata(conn, "gtfobins_last_sync") or "Never"
    total_entries = conn.execute("SELECT COUNT(*) as c FROM gtfobins").fetchone()["c"]

    if close_conn:
        conn.close()

    # HEAD request to check ETag / Last-Modified without downloading
    try:
        req = urllib.request.Request(
            GTFOBINS_REPO_ZIP,
            method="HEAD",
            headers={"User-Agent": "vectra-engine/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            remote_etag = resp.headers.get("ETag", "") or resp.headers.get("Last-Modified", "")
    except Exception as e:
        return {
            "error": str(e),
            "has_updates": False,
            "current_etag": current_etag,
            "remote_etag": "Unknown",
            "last_sync": last_sync,
            "total_entries": total_entries,
        }

    # If no ETag available, treat as stale if never synced
    if not remote_etag:
        has_updates = (total_entries == 0)
    else:
        has_updates = (total_entries == 0) or (not current_etag) or (current_etag != remote_etag)

    return {
        "error": None,
        "has_updates": has_updates,
        "current_etag": current_etag or "None (never synced)",
        "remote_etag": remote_etag or "N/A",
        "last_sync": last_sync,
        "total_entries": total_entries,
    }

def parse_gtfobins_archive(zip_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse all GTFOBins markdown/yaml recipe files from the GitHub repository zip archive."""
    import yaml
    import io
    all_entries = []
    raw_bins = {}

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
        for filename in z.namelist():
            if "/_gtfobins/" in filename and not filename.endswith("/"):
                base_name = Path(filename).name
                try:
                    content = z.read(filename).decode("utf-8", errors="ignore")
                    data = yaml.safe_load(content)
                    if isinstance(data, dict) and isinstance(data.get("functions"), dict):
                        raw_bins[base_name] = data["functions"]
                except Exception:
                    continue

    for binary_name, functions in raw_bins.items():
        if not isinstance(functions, dict):
            continue
        url = f"https://gtfobins.github.io/gtfobins/{binary_name}/"
        for func_name, code_blocks in functions.items():
            if not isinstance(code_blocks, list):
                continue
            for block in code_blocks:
                if not isinstance(block, dict):
                    if isinstance(block, str):
                        all_entries.append({
                            "binary": binary_name,
                            "function": func_name,
                            "description": "",
                            "code": block.strip(),
                            "url": url,
                        })
                    continue

                code = block.get("code", "")
                desc = block.get("description") or block.get("comment") or ""
                inherited_from = block.get("from")
                contexts = block.get("contexts", {})

                all_entries.append({
                    "binary": binary_name,
                    "function": func_name,
                    "description": desc.strip(),
                    "code": code.strip(),
                    "url": url,
                })

                if isinstance(contexts, dict):
                    for ctx in ("sudo", "suid", "capabilities"):
                        if ctx in contexts:
                            ctx_code = code.strip()
                            if ctx == "sudo" and not ctx_code.startswith("sudo"):
                                ctx_code = f"sudo {ctx_code}"
                            elif ctx == "suid" and not ctx_code.startswith("./") and not ctx_code.startswith("/"):
                                ctx_code = f"./{ctx_code}"

                            all_entries.append({
                                "binary": binary_name,
                                "function": ctx,
                                "description": f"[{ctx.upper()}] {desc}".strip(),
                                "code": ctx_code,
                                "url": url,
                            })

                if inherited_from and inherited_from in raw_bins:
                    target_funcs = raw_bins[inherited_from]
                    for t_func, t_blocks in target_funcs.items():
                        if t_func == "inherit" or not isinstance(t_blocks, list):
                            continue
                        for tb in t_blocks:
                            if isinstance(tb, dict):
                                t_code = tb.get("code", "")
                                adapted_code = t_code.replace(inherited_from, binary_name)
                                t_desc = tb.get("description") or tb.get("comment") or f"Inherited from {inherited_from}"
                                t_ctxs = tb.get("contexts", {})

                                all_entries.append({
                                    "binary": binary_name,
                                    "function": t_func,
                                    "description": f"Inherited from {inherited_from}: {t_desc}".strip(),
                                    "code": adapted_code.strip(),
                                    "url": url,
                                })

                                if isinstance(t_ctxs, dict):
                                    for ctx in ("sudo", "suid", "capabilities"):
                                        if ctx in t_ctxs:
                                            ctx_code = adapted_code.strip()
                                            if ctx == "sudo" and not ctx_code.startswith("sudo"):
                                                ctx_code = f"sudo {ctx_code}"
                                            elif ctx == "suid" and not ctx_code.startswith("./") and not ctx_code.startswith("/"):
                                                ctx_code = f"./{ctx_code}"

                                            all_entries.append({
                                                "binary": binary_name,
                                                "function": ctx,
                                                "description": f"[{ctx.upper()}] Inherited from {inherited_from}: {t_desc}".strip(),
                                                "code": ctx_code,
                                                "url": url,
                                            })

    # Deduplicate entries strictly
    unique_map = {}
    for e in all_entries:
        code_norm = " ".join(e["code"].split())
        key = (e["binary"].lower(), e["function"].lower(), code_norm)
        if key not in unique_map:
            unique_map[key] = e

    return list(unique_map.values())

def download_and_sync_gtfobins(
    conn: Optional[sqlite3.Connection] = None,
    callback=None,
    force: bool = False
) -> int:
    """Download GTFOBins repository zip, parse all binary exploitation recipes, and store in SQLite.
    
    Skips download if ETag matches upstream (already up-to-date), unless force=True.
    """
    import time
    GTFOBINS_REPO_ZIP, _ = _get_config()
    get_db_connection, init_db, save_gtfobins_batch, set_metadata, get_metadata = _get_db()

    init_db()
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    # ETag check — skip if already up-to-date
    if not force:
        current_etag = get_metadata(conn, "gtfobins_etag") or ""
        total_entries = conn.execute("SELECT COUNT(*) as c FROM gtfobins").fetchone()["c"]
        if current_etag and total_entries > 0:
            try:
                req = urllib.request.Request(
                    GTFOBINS_REPO_ZIP,
                    method="HEAD",
                    headers={"User-Agent": "vectra-engine/1.0"}
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    remote_etag = resp.headers.get("ETag", "") or resp.headers.get("Last-Modified", "")
                if remote_etag and remote_etag == current_etag:
                    if callback:
                        callback(f"GTFOBins already up-to-date ({total_entries:,} entries). Use --force to re-sync.")
                    if close_conn:
                        conn.close()
                    return total_entries
            except Exception:
                pass  # On network error, proceed with download

    if callback:
        callback("Downloading GTFOBins repository archive...")

    req = urllib.request.Request(
        GTFOBINS_REPO_ZIP,
        headers={"User-Agent": "vectra-engine/1.0"}
    )

    # Capture ETag from the actual GET response
    remote_etag = ""
    with urllib.request.urlopen(req, timeout=60) as resp:
        remote_etag = resp.headers.get("ETag", "") or resp.headers.get("Last-Modified", "")
        zip_bytes = resp.read()

    if callback:
        callback("Parsing GTFOBins recipes and resolving contexts...")

    all_entries = parse_gtfobins_archive(zip_bytes)
    save_gtfobins_batch(conn, all_entries)

    # Persist ETag and sync timestamp
    sync_ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    if remote_etag:
        set_metadata(conn, "gtfobins_etag", remote_etag)
    set_metadata(conn, "gtfobins_last_sync", sync_ts)

    if callback:
        callback(f"Successfully indexed {len(all_entries)} GTFOBins functions across {len(set(e['binary'] for e in all_entries))} binaries!")

    if close_conn:
        conn.close()

    return len(all_entries)

def search_gtfobins(
    query: str = "",
    function_type: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """Search GTFOBins by binary name, function (sudo, suid, shell, etc.), with strict zero-duplicate guarantee."""
    get_db_connection, _, _, _, _ = _get_db()
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    sql_parts = ["SELECT id, binary, function, description, code, url, date_added FROM gtfobins WHERE 1=1"]
    params = []

    if query:
        clean_q = query.strip().lower()
        exact_bin_check = conn.execute(
            "SELECT COUNT(*) as c FROM gtfobins WHERE LOWER(binary) = ? OR LOWER(binary) LIKE ?",
            (clean_q, f"%{clean_q}%")
        ).fetchone()["c"]
        if exact_bin_check > 0:
            sql_parts.append("AND (LOWER(binary) = ? OR LOWER(binary) LIKE ?)")
            params.extend([clean_q, f"%{clean_q}%"])
        else:
            sql_parts.append("AND id IN (SELECT rowid FROM gtfobins_fts WHERE gtfobins_fts MATCH ?)")
            params.append(f'"{clean_q}"*')

    if function_type:
        clean_f = function_type.strip().lower()
        sql_parts.append("AND LOWER(function) = ?")
        params.append(clean_f)

    sql_parts.append("ORDER BY binary ASC, function ASC LIMIT ?")
    params.append(limit * 3)

    query_str = " ".join(sql_parts)
    rows = conn.execute(query_str, params).fetchall()

    # Strict deduplication: ensure no repeated command payload is returned
    seen = set()
    deduped_results = []
    for r in rows:
        row_dict = dict(r)
        code_norm = " ".join(row_dict["code"].split())
        dedup_key = (row_dict["binary"].lower(), code_norm)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        deduped_results.append(row_dict)
        if len(deduped_results) >= limit:
            break

    if close_conn:
        conn.close()

    return deduped_results

def list_gtfobins_functions(conn: Optional[sqlite3.Connection] = None) -> List[str]:
    """Get all unique GTFOBins function types."""
    get_db_connection, _, _, _, _ = _get_db()
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    rows = conn.execute("SELECT DISTINCT function FROM gtfobins ORDER BY function ASC;").fetchall()
    funcs = [r["function"] for r in rows]

    if close_conn:
        conn.close()

    return funcs
