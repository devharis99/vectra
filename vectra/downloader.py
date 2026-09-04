import os
import json
import zipfile
import urllib.request
import time
from pathlib import Path
from typing import Optional, Callable, Dict, Any
from vectra.config import CVEPROJECT_RELEASE_API, DB_BATCH_SIZE, DB_PATH, DEFAULT_DATA_DIR
from vectra.db import get_db_connection, init_db, save_cves_batch, set_metadata
from vectra.parser import parse_cve_v5

def fetch_latest_release_info() -> Dict[str, Any]:
    """Query GitHub API for the latest CVEProject/cvelistV5 release details."""
    req = urllib.request.Request(
        CVEPROJECT_RELEASE_API,
        headers={"User-Agent": "vectra-engine/1.0"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        
    tag_name = data.get("tag_name", "")
    assets = data.get("assets", [])
    
    full_zip_url = None
    full_zip_size = 0
    delta_zip_url = None
    
    for asset in assets:
        name = asset.get("name", "")
        url = asset.get("browser_download_url", "")
        size = asset.get("size", 0)
        
        if "all_CVEs_at_midnight" in name:
            full_zip_url = url
            full_zip_size = size
        elif "delta_CVEs" in name:
            delta_zip_url = url
            
    if not full_zip_url and data.get("zipball_url"):
        full_zip_url = data.get("zipball_url")
        
    return {
        "tag_name": tag_name,
        "full_zip_url": full_zip_url,
        "full_zip_size": full_zip_size,
        "delta_zip_url": delta_zip_url,
    }

def download_file_with_progress(
    url: str,
    target_path: Path,
    progress_callback: Optional[Callable[[int, int, float], None]] = None,
    max_retries: int = 15
):
    """Download a file with HTTP Range resume support, timeout protection, and automatic retries."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target_path.with_suffix(".download")
    
    downloaded = 0
    if temp_path.exists():
        downloaded = temp_path.stat().st_size

    total_size = 0
    try:
        head_req = urllib.request.Request(url, headers={"User-Agent": "vectra-engine/1.0"})
        with urllib.request.urlopen(head_req, timeout=30) as resp:
            total_size = int(resp.headers.get("Content-Length", 0))
    except Exception:
        pass

    chunk_size = 1024 * 512
    retries = 0

    while retries < max_retries:
        try:
            headers = {"User-Agent": "vectra-engine/1.0"}
            if downloaded > 0:
                headers["Range"] = f"bytes={downloaded}-"
                
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=45) as resp:
                if resp.status == 200 and downloaded > 0 and headers.get("Range"):
                    downloaded = 0
                    mode = "wb"
                else:
                    mode = "ab" if downloaded > 0 else "wb"
                    
                if not total_size:
                    total_size = int(resp.headers.get("Content-Length", 0)) + downloaded
                    
                start_time = time.time()
                initial_dl = downloaded

                with open(temp_path, mode) as f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        elapsed = time.time() - start_time
                        speed = (downloaded - initial_dl) / elapsed if elapsed > 0 else 0
                        if progress_callback:
                            progress_callback(downloaded, total_size, speed)
                            
            if total_size and downloaded >= total_size:
                break
            elif not total_size and downloaded > 0:
                break
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, Exception) as e:
            retries += 1
            if retries >= max_retries:
                raise RuntimeError(f"Download failed after {max_retries} attempts: {e}")
            time.sleep(2)
            if temp_path.exists():
                downloaded = temp_path.stat().st_size

    temp_path.replace(target_path)

def ingest_cve_zip(
    zip_path: Path,
    max_records: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None
) -> int:
    """Stream-parse JSON files inside the CVE zip archive (handling nested zip if needed) directly into SQLite."""
    init_db()
    conn = get_db_connection()
    
    # Check if outer zip contains inner cves.zip
    actual_zip = zip_path
    temp_extracted_inner = None
    
    try:
        with zipfile.ZipFile(zip_path, "r") as z_test:
            if "cves.zip" in z_test.namelist():
                extracted_path = zip_path.parent / "cves.zip"
                if not extracted_path.exists():
                    z_test.extract("cves.zip", path=zip_path.parent)
                actual_zip = extracted_path
    except Exception:
        pass

    total_parsed = 0
    batch = []
    
    with zipfile.ZipFile(actual_zip, "r") as z:
        file_list = [f for f in z.namelist() if f.endswith(".json") and "CVE-" in f]
        total_files = len(file_list)
        if max_records:
            file_list = file_list[:max_records]
            total_files = len(file_list)
            
        for idx, filename in enumerate(file_list, 1):
            try:
                raw_bytes = z.read(filename)
                data = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
                cve_row = parse_cve_v5(data)
                if cve_row:
                    batch.append(cve_row)
                    total_parsed += 1
            except Exception:
                continue
                
            if len(batch) >= DB_BATCH_SIZE:
                save_cves_batch(conn, batch)
                batch.clear()
                if progress_callback:
                    cve_id = cve_row["cve_id"] if cve_row else ""
                    progress_callback(idx, total_files, cve_id)
                    
        if batch:
            save_cves_batch(conn, batch)
            batch.clear()
            if progress_callback:
                progress_callback(total_files, total_files, "Finalizing index...")
                
    set_metadata(conn, "last_sync", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    set_metadata(conn, "source_archive", actual_zip.name)
    conn.close()
    return total_parsed
