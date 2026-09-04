import sqlite3
import json
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from vectra.config import DB_PATH

def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db(db_path: Optional[Path] = None):
    """Create all required tables, triggers, and FTS5 indexes."""
    conn = get_db_connection(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                state TEXT,
                assigner TEXT,
                date_published TEXT,
                date_updated TEXT,
                year INTEGER,
                title TEXT,
                description TEXT,
                cvss_v3_score REAL,
                cvss_v3_severity TEXT,
                cvss_v3_vector TEXT,
                cvss_v2_score REAL,
                cwe_ids TEXT,
                vuln_types TEXT,
                affected_vendors TEXT,
                affected_products TEXT,
                affected_versions TEXT,
                references_json TEXT,
                raw_json TEXT
            );
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_year ON cves(year);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(cvss_v3_severity);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(cvss_v3_score);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(date_published);")

        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
                cve_id UNINDEXED,
                title,
                description,
                affected_vendors,
                affected_products,
                affected_versions,
                cwe_ids,
                vuln_types,
                tokenize='porter unicode61'
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS gtfobins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binary TEXT,
                function TEXT,
                description TEXT,
                code TEXT,
                url TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gtfo_binary ON gtfobins(binary);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gtfo_function ON gtfobins(function);")

        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS gtfobins_fts USING fts5(
                binary,
                function,
                description,
                code,
                tokenize='porter unicode61'
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

    conn.close()

def save_cves_batch(conn: sqlite3.Connection, cve_records: List[Dict[str, Any]]):
    """Insert or replace a batch of CVE records into both structured and FTS tables."""
    if not cve_records:
        return
    
    clean_records = []
    for r in cve_records:
        clean_records.append({
            "cve_id": r.get("cve_id", ""),
            "state": r.get("state", "PUBLISHED"),
            "assigner": r.get("assigner", ""),
            "date_published": r.get("date_published", ""),
            "date_updated": r.get("date_updated", ""),
            "year": r.get("year"),
            "title": r.get("title", ""),
            "description": r.get("description", ""),
            "cvss_v3_score": r.get("cvss_v3_score"),
            "cvss_v3_severity": r.get("cvss_v3_severity", ""),
            "cvss_v3_vector": r.get("cvss_v3_vector", ""),
            "cvss_v2_score": r.get("cvss_v2_score"),
            "cwe_ids": r.get("cwe_ids", ""),
            "vuln_types": r.get("vuln_types", ""),
            "affected_vendors": r.get("affected_vendors", ""),
            "affected_products": r.get("affected_products", ""),
            "affected_versions": r.get("affected_versions", ""),
            "references_json": r.get("references_json", "[]"),
            "raw_json": r.get("raw_json", "[]"),
        })

    with conn:
        conn.executemany("""
            INSERT OR REPLACE INTO cves (
                cve_id, state, assigner, date_published, date_updated, year,
                title, description, cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
                cvss_v2_score, cwe_ids, vuln_types, affected_vendors,
                affected_products, affected_versions, references_json, raw_json
            ) VALUES (
                :cve_id, :state, :assigner, :date_published, :date_updated, :year,
                :title, :description, :cvss_v3_score, :cvss_v3_severity, :cvss_v3_vector,
                :cvss_v2_score, :cwe_ids, :vuln_types, :affected_vendors,
                :affected_products, :affected_versions, :references_json, :raw_json
            );
        """, clean_records)

        for r in clean_records:
            conn.execute("DELETE FROM cves_fts WHERE cve_id = ?", (r["cve_id"],))
            conn.execute("""
                INSERT INTO cves_fts (
                    cve_id, title, description, affected_vendors,
                    affected_products, affected_versions, cwe_ids, vuln_types
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                r["cve_id"],
                r["title"] or "",
                r["description"] or "",
                r["affected_vendors"] or "",
                r["affected_products"] or "",
                r["affected_versions"] or "",
                r["cwe_ids"] or "",
                r["vuln_types"] or "",
            ))

def save_gtfobins_batch(conn: sqlite3.Connection, entries: List[Dict[str, Any]]):
    with conn:
        conn.execute("DELETE FROM gtfobins;")
        conn.execute("DELETE FROM gtfobins_fts;")
        for entry in entries:
            conn.execute("""
                INSERT INTO gtfobins (binary, function, description, code, url)
                VALUES (?, ?, ?, ?, ?);
            """, (entry["binary"], entry["function"], entry.get("description", ""), entry.get("code", ""), entry.get("url", "")))
            conn.execute("""
                INSERT INTO gtfobins_fts (binary, function, description, code)
                VALUES (?, ?, ?, ?);
            """, (entry["binary"], entry["function"], entry.get("description", ""), entry.get("code", "")))

def set_metadata(conn: sqlite3.Connection, key: str, value: str):
    with conn:
        conn.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?);", (key, value))

def get_metadata(conn: sqlite3.Connection, key: str) -> Optional[str]:
    row = conn.execute("SELECT value FROM metadata WHERE key = ?;", (key,)).fetchone()
    return row["value"] if row else None

def seed_common_cves(conn: sqlite3.Connection):
    from vectra.seeds import COMMON_CVES
    save_cves_batch(conn, COMMON_CVES)
