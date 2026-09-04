import yaml
import sqlite3
import zipfile
import io
import urllib.request
from pathlib import Path
from typing import List, Dict, Any, Optional
from vectra.config import GTFOBINS_REPO_ZIP, DB_PATH
from vectra.db import get_db_connection, save_gtfobins_batch, init_db

def parse_gtfobins_archive(zip_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse all GTFOBins recipes from zip and resolve inheritance/contexts."""
    raw_bins = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for filename in z.namelist():
            if "/_gtfobins/" in filename and not filename.endswith("/"):
                binary_name = filename.split("/")[-1].replace(".md", "")
                if not binary_name:
                    continue
                try:
                    yaml_text = z.read(filename).decode("utf-8", errors="ignore")
                    content = yaml_text.strip()
                    if content.startswith("---"):
                        parts = content.split("---")
                        for p in parts:
                            if "functions:" in p:
                                content = p
                                break
                    data = yaml.safe_load(content)
                    if isinstance(data, dict) and "functions" in data and isinstance(data["functions"], dict):
                        raw_bins[binary_name] = data["functions"]
                except Exception:
                    continue

    all_entries = []

    # Second pass: resolve entries and inheritance
    for binary_name, functions in raw_bins.items():
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

                # Primary function entry
                all_entries.append({
                    "binary": binary_name,
                    "function": func_name,
                    "description": desc.strip(),
                    "code": code.strip(),
                    "url": url,
                })

                # If this entry supports sudo/suid contexts, register context-specific entries
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

                # If inherited from another binary (e.g. vim inherits from vi), copy referenced functions
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

    # Deduplicate entries
    unique_map = {}
    for e in all_entries:
        key = (e["binary"], e["function"], e["code"])
        if key not in unique_map:
            unique_map[key] = e

    return list(unique_map.values())

def download_and_sync_gtfobins(conn: Optional[sqlite3.Connection] = None, callback=None) -> int:
    """Download GTFOBins repository zip, parse all binary exploitation recipes, and store in SQLite."""
    init_db()
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    if callback:
        callback("Downloading GTFOBins repository archive...")

    req = urllib.request.Request(
        GTFOBINS_REPO_ZIP,
        headers={"User-Agent": "vectra-engine/1.0"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        zip_bytes = resp.read()

    if callback:
        callback("Parsing GTFOBins recipes and resolving contexts...")

    all_entries = parse_gtfobins_archive(zip_bytes)
    save_gtfobins_batch(conn, all_entries)

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
    """Search GTFOBins by binary name, function (sudo, suid, shell, etc.), or code keyword."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    sql_parts = ["SELECT id, binary, function, description, code, url FROM gtfobins WHERE 1=1"]
    params = []

    if query:
        clean_q = query.strip().lower()
        # First check if there's an exact or prefix match on binary column
        exact_bin_check = conn.execute("SELECT COUNT(*) as c FROM gtfobins WHERE LOWER(binary) = ? OR LOWER(binary) LIKE ?", (clean_q, f"{clean_q}%")).fetchone()["c"]
        if exact_bin_check > 0:
            sql_parts.append("AND (LOWER(binary) = ? OR LOWER(binary) LIKE ?)")
            params.extend([clean_q, f"{clean_q}%"])
        else:
            # Fallback to full-text search across description/code
            sql_parts.append("AND id IN (SELECT rowid FROM gtfobins_fts WHERE gtfobins_fts MATCH ?)")
            params.append(f'"{clean_q}"*')

    if function_type:
        clean_f = function_type.strip().lower()
        sql_parts.append("AND LOWER(function) = ?")
        params.append(clean_f)

    sql_parts.append("ORDER BY binary ASC, function ASC LIMIT ?")
    params.append(limit)

    query_str = " ".join(sql_parts)
    rows = conn.execute(query_str, params).fetchall()
    results = [dict(r) for r in rows]

    if close_conn:
        conn.close()

    return results

def list_gtfobins_functions(conn: Optional[sqlite3.Connection] = None) -> List[str]:
    """Get all unique GTFOBins function types."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    rows = conn.execute("SELECT DISTINCT function FROM gtfobins ORDER BY function ASC;").fetchall()
    funcs = [r["function"] for r in rows]

    if close_conn:
        conn.close()

    return funcs
