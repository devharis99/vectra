import json
import re
from typing import Dict, Any, Optional, List, Tuple
from vectra.vuln_classifier import classify_vulnerability

def extract_year_from_cve(cve_id: str) -> Optional[int]:
    m = re.match(r"CVE-(\d{4})-", cve_id, re.I)
    return int(m.group(1)) if m else None

def parse_cve_v5(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse a CVE JSON 5.0 record into a flattened database row dictionary."""
    if not isinstance(data, dict):
        return None

    cve_meta = data.get("cveMetadata", {})
    cve_id = cve_meta.get("cveId")
    if not cve_id:
        return None

    state = cve_meta.get("state", "PUBLISHED")
    if state == "REJECTED":
        # Keep rejected record minimally or skip
        pass

    date_pub = cve_meta.get("datePublished") or cve_meta.get("dateReserved") or ""
    date_upd = cve_meta.get("dateUpdated") or ""
    year = extract_year_from_cve(cve_id)

    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    # Title
    title = cna.get("title") or ""

    # Description (prefer English)
    desc_list = cna.get("descriptions", [])
    desc_str = ""
    for d in desc_list:
        if isinstance(d, dict) and d.get("lang", "").startswith("en"):
            desc_str = d.get("value", "")
            break
    if not desc_str and desc_list and isinstance(desc_list[0], dict):
        desc_str = desc_list[0].get("value", "")

    # Metrics (CVSS v3.1, v3.0, v2.0)
    cvss_v3_score = None
    cvss_v3_severity = None
    cvss_v3_vector = ""
    cvss_v2_score = None

    metrics = cna.get("metrics", [])
    if isinstance(metrics, list):
        for m in metrics:
            if not isinstance(m, dict):
                continue
            for k, val in m.items():
                if not isinstance(val, dict):
                    continue
                k_lower = k.lower()
                if "cvssv3" in k_lower:
                    score = val.get("baseScore")
                    if score is not None and cvss_v3_score is None:
                        try:
                            cvss_v3_score = float(score)
                            cvss_v3_severity = (val.get("baseSeverity") or "").upper()
                            cvss_v3_vector = val.get("vectorString") or ""
                        except (ValueError, TypeError):
                            pass
                elif "cvssv2" in k_lower and cvss_v2_score is None:
                    score = val.get("baseScore")
                    if score is not None:
                        try:
                            cvss_v2_score = float(score)
                        except (ValueError, TypeError):
                            pass

    # Derive severity if missing but score exists
    if cvss_v3_score is not None and not cvss_v3_severity:
        if cvss_v3_score >= 9.0:
            cvss_v3_severity = "CRITICAL"
        elif cvss_v3_score >= 7.0:
            cvss_v3_severity = "HIGH"
        elif cvss_v3_score >= 4.0:
            cvss_v3_severity = "MEDIUM"
        else:
            cvss_v3_severity = "LOW"

    # Problem types / CWEs
    cwe_set = set()
    problem_types = cna.get("problemTypes", [])
    if isinstance(problem_types, list):
        for pt in problem_types:
            if isinstance(pt, dict):
                for desc in pt.get("descriptions", []):
                    if isinstance(desc, dict):
                        cwe_id = desc.get("cweId")
                        if cwe_id:
                            cwe_set.add(cwe_id.strip())
                        val = desc.get("description", "")
                        cwe_matches = re.findall(r"\bCWE-\d+\b", val, re.I)
                        for cm in cwe_matches:
                            cwe_set.add(cm.upper())

    cwe_ids_str = ", ".join(sorted(list(cwe_set)))

    # Affected Vendors, Products, and Versions
    vendors = set()
    products = set()
    version_tokens = set()
    version_details = []

    affected_list = cna.get("affected", [])
    if isinstance(affected_list, list):
        for aff in affected_list:
            if not isinstance(aff, dict):
                continue
            v = aff.get("vendor", "").strip()
            p = aff.get("product", "").strip()
            if v and v.lower() != "n/a":
                vendors.add(v)
            if p and p.lower() != "n/a":
                products.add(p)

            for ver_obj in aff.get("versions", []):
                if not isinstance(ver_obj, dict):
                    continue
                ver_val = str(ver_obj.get("version", "")).strip()
                status = ver_obj.get("status", "")
                less_than = ver_obj.get("lessThan", "")
                
                if ver_val and ver_val.lower() not in ("n/a", "unspecified", "0"):
                    version_tokens.add(ver_val)
                if less_than:
                    version_tokens.add(str(less_than))

                version_details.append({
                    "vendor": v,
                    "product": p,
                    "version": ver_val,
                    "status": status,
                    "lessThan": less_than
                })

    vendors_str = ", ".join(sorted(list(vendors)))
    products_str = ", ".join(sorted(list(products)))
    versions_str = " ".join(sorted(list(version_tokens)))

    # Vulnerability classification (e.g. rce, privesc, sqli, xss, lfi, etc.)
    vuln_types = classify_vulnerability(list(cwe_set), title, desc_str)
    vuln_types_str = ", ".join(vuln_types)

    # References
    refs = []
    for r in cna.get("references", []):
        if isinstance(r, dict) and r.get("url"):
            refs.append(r["url"])
    refs_json = json.dumps(refs[:15]) if refs else "[]"
    versions_json = json.dumps(version_details[:30]) if version_details else "[]"

    return {
        "cve_id": cve_id,
        "state": state,
        "assigner": cve_meta.get("assignerShortName") or "",
        "date_published": date_pub,
        "date_updated": date_upd,
        "year": year,
        "title": title,
        "description": desc_str,
        "cvss_v3_score": cvss_v3_score,
        "cvss_v3_severity": cvss_v3_severity,
        "cvss_v3_vector": cvss_v3_vector,
        "cvss_v2_score": cvss_v2_score,
        "cwe_ids": cwe_ids_str,
        "vuln_types": vuln_types_str,
        "affected_vendors": vendors_str,
        "affected_products": products_str,
        "affected_versions": versions_str,
        "references_json": refs_json,
        "raw_json": versions_json,
    }
