import sqlite3
import re
import json
from typing import List, Dict, Any, Optional, Tuple
from vectra.config import DB_PATH
from vectra.db import get_db_connection
from vectra.vuln_classifier import normalize_vuln_type

def clean_fts_query(text: str) -> str:
    """Sanitize and format query string for SQLite FTS5 matching."""
    # Remove special FTS5 operators to prevent syntax errors
    clean = re.sub(r'["\'\*\+\^\:\(\)\{\}\[\]\-\~]', ' ', text)
    tokens = [t.strip() for t in clean.split() if t.strip()]
    if not tokens:
        return ""
    # Prefix match on tokens
    return " ".join([f'"{t}"*' if not t.isdigit() else f'"{t}"' for t in tokens])

def extract_service_and_version(query: str) -> Tuple[str, Optional[str]]:
    """Detect if the query string contains a software service name and version number."""
    # Matches patterns like 'apache 2.4.49', 'openssh 8.2p1', 'sudo 1.8.31', 'nginx 1.18.0'
    m = re.search(r'\b([a-zA-Z\-_]+)\s+([vV]?\d+(\.\d+)+[a-zA-Z0-9_\-\.]*)\b', query)
    if m:
        service = m.group(1).strip()
        version = m.group(2).strip().lstrip("vV")
        return service, version
    return query, None

def search_cves(
    query: str = "",
    service: Optional[str] = None,
    version: Optional[str] = None,
    vuln_type: Optional[str] = None,
    severity: Optional[str] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    year: Optional[int] = None,
    cwe: Optional[str] = None,
    limit: int = 25,
    offset: int = 0,
    conn: Optional[sqlite3.Connection] = None
) -> Dict[str, Any]:
    """Execute a multi-criteria search over CVE records with FTS5 ranking and structured filters."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    # Auto-extract service and version if user typed them together in query
    if query and not service and not version:
        detected_service, detected_ver = extract_service_and_version(query)
        if detected_ver:
            service = detected_service
            version = detected_ver
            query = ""  # Filter using specific service and version criteria

    sql_conditions = ["c.state = 'PUBLISHED'"]
    params: List[Any] = []
    fts_clauses = []

    # 1. Full-text query on description/title
    if query:
        # Check if query is an exact CVE-ID
        if re.match(r"^CVE-\d{4}-\d+$", query.strip(), re.I):
            sql_conditions.append("c.cve_id = ?")
            params.append(query.strip().upper())
        else:
            fts_query = clean_fts_query(query)
            if fts_query:
                fts_clauses.append(fts_query)

    # 2. Service name filtering
    if service:
        srv_clean = service.strip()
        sql_conditions.append("(c.affected_products LIKE ? OR c.affected_vendors LIKE ? OR c.title LIKE ?)")
        params.extend([f"%{srv_clean}%", f"%{srv_clean}%", f"%{srv_clean}%"])

    # 3. Version filtering
    if version:
        ver_clean = version.strip().lstrip("vV")
        sql_conditions.append("(c.affected_versions LIKE ? OR c.description LIKE ? OR c.title LIKE ?)")
        params.extend([f"%{ver_clean}%", f"%{ver_clean}%", f"%{ver_clean}%"])

    # 4. Vulnerability type filtering (e.g. rce, privesc, sqli, xss)
    if vuln_type:
        norm_type = normalize_vuln_type(vuln_type)
        sql_conditions.append("c.vuln_types LIKE ?")
        params.append(f"%{norm_type}%")

    # 5. Severity filtering
    if severity:
        sev_clean = severity.strip().upper()
        sql_conditions.append("c.cvss_v3_severity = ?")
        params.append(sev_clean)

    # 6. CVSS score range
    if min_score is not None:
        sql_conditions.append("c.cvss_v3_score >= ?")
        params.append(min_score)
    if max_score is not None:
        sql_conditions.append("c.cvss_v3_score <= ?")
        params.append(max_score)

    # 7. Year filtering
    if year:
        sql_conditions.append("c.year = ?")
        params.append(year)

    # 8. CWE filtering
    if cwe:
        cwe_clean = cwe.strip().upper()
        if not cwe_clean.startswith("CWE-"):
            cwe_clean = f"CWE-{cwe_clean}"
        sql_conditions.append("c.cwe_ids LIKE ?")
        params.append(f"%{cwe_clean}%")

    # Build SQL statement
    where_clause = " AND ".join(sql_conditions)
    
    if fts_clauses:
        fts_match_str = " AND ".join(fts_clauses)
        base_query = f"""
            SELECT c.*, snippet(cves_fts, 2, '<b>', '</b>', '...', 20) as snippet_desc
            FROM cves c
            JOIN cves_fts ON c.cve_id = cves_fts.cve_id
            WHERE cves_fts MATCH ? AND {where_clause}
            ORDER BY c.cvss_v3_score DESC NULLS LAST, c.date_published DESC
            LIMIT ? OFFSET ?;
        """
        exec_params = [fts_match_str] + params + [limit, offset]
        count_query = f"""
            SELECT COUNT(*) as total
            FROM cves c
            JOIN cves_fts ON c.cve_id = cves_fts.cve_id
            WHERE cves_fts MATCH ? AND {where_clause};
        """
        count_params = [fts_match_str] + params
    else:
        base_query = f"""
            SELECT c.*, substr(c.description, 1, 200) as snippet_desc
            FROM cves c
            WHERE {where_clause}
            ORDER BY c.cvss_v3_score DESC NULLS LAST, c.date_published DESC
            LIMIT ? OFFSET ?;
        """
        exec_params = params + [limit, offset]
        count_query = f"SELECT COUNT(*) as total FROM cves c WHERE {where_clause};"
        count_params = params

    total_count = conn.execute(count_query, count_params).fetchone()["total"]
    rows = conn.execute(base_query, exec_params).fetchall()
    
    results = []
    for r in rows:
        row_dict = dict(r)
        # Parse JSON fields
        try:
            row_dict["references"] = json.loads(row_dict.get("references_json") or "[]")
        except Exception:
            row_dict["references"] = []
        try:
            row_dict["version_details"] = json.loads(row_dict.get("raw_json") or "[]")
        except Exception:
            row_dict["version_details"] = []
        results.append(row_dict)

    if close_conn:
        conn.close()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "results": results
    }

def get_cve_by_id(cve_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
    """Retrieve full details of a single CVE record."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    clean_id = cve_id.strip().upper()
    row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (clean_id,)).fetchone()
    if not row:
        if close_conn:
            conn.close()
        return None

    res = dict(row)
    try:
        res["references"] = json.loads(res.get("references_json") or "[]")
    except Exception:
        res["references"] = []
    try:
        res["version_details"] = json.loads(res.get("raw_json") or "[]")
    except Exception:
        res["version_details"] = []

    if close_conn:
        conn.close()
    return res

def get_database_stats(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    """Calculate aggregate statistics of the local CVE & GTFOBins database."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    total_cves = conn.execute("SELECT COUNT(*) as c FROM cves").fetchone()["c"]
    total_gtfo = conn.execute("SELECT COUNT(*) as c FROM gtfobins").fetchone()["c"]
    total_gtfo_bins = conn.execute("SELECT COUNT(DISTINCT binary) as c FROM gtfobins").fetchone()["c"]

    # Severity distribution
    sev_rows = conn.execute("""
        SELECT cvss_v3_severity, COUNT(*) as count
        FROM cves
        WHERE cvss_v3_severity IS NOT NULL AND cvss_v3_severity != ''
        GROUP BY cvss_v3_severity
        ORDER BY count DESC;
    """).fetchall()
    severity_dist = {r["cvss_v3_severity"]: r["count"] for r in sev_rows}

    # Top vulnerability types
    types_count = {}
    for r in conn.execute("SELECT vuln_types FROM cves WHERE vuln_types != ''").fetchall():
        for t in r["vuln_types"].split(","):
            t_clean = t.strip()
            if t_clean:
                types_count[t_clean] = types_count.get(t_clean, 0) + 1
    top_vuln_types = dict(sorted(types_count.items(), key=lambda x: x[1], reverse=True)[:10])

    # Recent sync time
    meta_sync = conn.execute("SELECT value FROM metadata WHERE key = 'last_sync'").fetchone()
    last_sync = meta_sync["value"] if meta_sync else "Never"

    if close_conn:
        conn.close()

    return {
        "total_cves": total_cves,
        "total_gtfo_entries": total_gtfo,
        "total_gtfo_binaries": total_gtfo_bins,
        "severity_distribution": severity_dist,
        "top_vulnerability_types": top_vuln_types,
        "last_sync": last_sync,
    }
