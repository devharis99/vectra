from fastapi import FastAPI, Query, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import threading

from vectra.search import search_cves, get_cve_by_id, get_database_stats
from vectra.gtfobins import search_gtfobins, list_gtfobins_functions, download_and_sync_gtfobins
from vectra.downloader import fetch_latest_release_info, download_file_with_progress, ingest_cve_zip
from vectra.config import DEFAULT_DATA_DIR

app = FastAPI(
    title="CVE & GTFOBins Local Search API",
    description="High-performance offline vulnerability & exploit search engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SYNC_STATUS = {
    "is_syncing": False,
    "progress": 0,
    "total": 0,
    "message": "Idle",
    "error": None
}

@app.get("/api/search")
def api_search(
    q: str = Query("", description="Keywords or software/service query"),
    service: Optional[str] = None,
    version: Optional[str] = None,
    type: Optional[str] = None,
    severity: Optional[str] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    year: Optional[int] = None,
    cwe: Optional[str] = None,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    return search_cves(
        query=q,
        service=service,
        version=version,
        vuln_type=type,
        severity=severity,
        min_score=min_score,
        max_score=max_score,
        year=year,
        cwe=cwe,
        limit=limit,
        offset=offset
    )

@app.get("/api/cve/{cve_id}")
def api_get_cve(cve_id: str):
    res = get_cve_by_id(cve_id)
    if not res:
        raise HTTPException(status_code=404, detail="CVE not found")
    return res

@app.get("/api/gtfo")
def api_gtfo(
    binary: str = Query("", description="Binary name"),
    type: Optional[str] = Query(None, description="Exploit function category"),
    limit: int = 50
):
    return search_gtfobins(query=binary, function_type=type, limit=limit)

@app.get("/api/gtfo/functions")
def api_gtfo_functions():
    return list_gtfobins_functions()

@app.get("/api/stats")
def api_stats():
    return get_database_stats()

@app.get("/api/sync/status")
def api_sync_status():
    return SYNC_STATUS

def run_sync_task():
    global SYNC_STATUS
    SYNC_STATUS["is_syncing"] = True
    SYNC_STATUS["error"] = None
    try:
        SYNC_STATUS["message"] = "Syncing GTFOBins..."
        download_and_sync_gtfobins()
        
        SYNC_STATUS["message"] = "Fetching CVE list..."
        rel = fetch_latest_release_info()
        tag = rel.get("tag_name")
        zip_url = rel.get("full_zip_url")
        if zip_url:
            dest_zip = DEFAULT_DATA_DIR / f"cvelist_{tag}.zip"
            if not dest_zip.exists():
                SYNC_STATUS["message"] = "Downloading CVE dataset..."
                def cb(cur, tot, spd):
                    SYNC_STATUS["progress"] = cur
                    SYNC_STATUS["total"] = tot
                download_file_with_progress(zip_url, dest_zip, cb)
            
            SYNC_STATUS["message"] = "Indexing CVE records..."
            def idx_cb(cur, tot, item):
                SYNC_STATUS["progress"] = cur
                SYNC_STATUS["total"] = tot
                SYNC_STATUS["message"] = f"Indexing {item}"
            ingest_cve_zip(dest_zip, progress_callback=idx_cb)

        SYNC_STATUS["message"] = "Sync complete!"
    except Exception as e:
        SYNC_STATUS["error"] = str(e)
        SYNC_STATUS["message"] = f"Error: {e}"
    finally:
        SYNC_STATUS["is_syncing"] = False

@app.post("/api/sync/start")
def api_start_sync(background_tasks: BackgroundTasks):
    global SYNC_STATUS
    if SYNC_STATUS["is_syncing"]:
        return {"status": "already_running"}
    background_tasks.add_task(run_sync_task)
    return {"status": "started"}
