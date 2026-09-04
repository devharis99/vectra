import re
from typing import List, Set

CWE_MAP = {
    # RCE / Code Execution / Injection
    "CWE-94": "rce",
    "CWE-78": "rce",
    "CWE-77": "rce",
    "CWE-502": "rce",  # Deserialization of Untrusted Data
    "CWE-95": "rce",   # Eval Injection
    "CWE-917": "rce",  # Expression Language Injection
    
    # Privilege Escalation / Authorization
    "CWE-269": "privesc",
    "CWE-264": "privesc",
    "CWE-250": "privesc",
    "CWE-276": "privesc",
    "CWE-732": "privesc",
    "CWE-863": "privesc",
    
    # SQL Injection
    "CWE-89": "sqli",
    
    # Cross-Site Scripting
    "CWE-79": "xss",
    "CWE-80": "xss",
    
    # Authentication & Access Control Bypass
    "CWE-287": "auth-bypass",
    "CWE-306": "auth-bypass",
    "CWE-284": "auth-bypass",
    "CWE-285": "auth-bypass",
    "CWE-640": "auth-bypass",
    "CWE-290": "auth-bypass",
    
    # Path Traversal / File Inclusion
    "CWE-22": "lfi",
    "CWE-23": "lfi",
    "CWE-73": "lfi",
    "CWE-98": "rfi",
    
    # Server-Side Request Forgery
    "CWE-918": "ssrf",
    
    # Denial of Service
    "CWE-400": "dos",
    "CWE-770": "dos",
    "CWE-476": "dos",  # NULL Pointer Dereference
    "CWE-835": "dos",  # Loop with Unreachable Exit Condition
    
    # Memory Corruption / Buffer Overflow
    "CWE-119": "memory-corruption",
    "CWE-120": "memory-corruption",
    "CWE-121": "memory-corruption",
    "CWE-122": "memory-corruption",
    "CWE-125": "memory-corruption",
    "CWE-787": "memory-corruption",
    "CWE-416": "memory-corruption",  # Use After Free
    "CWE-190": "memory-corruption",  # Integer Overflow
    
    # Information Disclosure
    "CWE-200": "info-leak",
    "CWE-209": "info-leak",
    "CWE-215": "info-leak",
    "CWE-538": "info-leak",
    
    # CSRF
    "CWE-352": "csrf",
    
    # XML / XXE
    "CWE-611": "xxe",
}

REGEX_PATTERNS = [
    (re.compile(r"\b(remote code execution|rce|arbitrary code execution|command injection|code injection)\b", re.I), "rce"),
    (re.compile(r"\b(privilege escalation|escalate privileges|gain root|gain admin|elevation of privilege|local privilege escalation|lpe)\b", re.I), "privesc"),
    (re.compile(r"\b(sql injection|sqli|blind sql)\b", re.I), "sqli"),
    (re.compile(r"\b(cross-site scripting|xss|reflected xss|stored xss|dom xss)\b", re.I), "xss"),
    (re.compile(r"\b(authentication bypass|bypass authentication|unauthenticated|bypass authorization|auth bypass)\b", re.I), "auth-bypass"),
    (re.compile(r"\b(path traversal|directory traversal|arbitrary file read|local file inclusion|lfi|file upload|arbitrary file write)\b", re.I), "lfi"),
    (re.compile(r"\b(server-side request forgery|ssrf)\b", re.I), "ssrf"),
    (re.compile(r"\b(denial of service|dos|crash|infinite loop|resource exhaustion)\b", re.I), "dos"),
    (re.compile(r"\b(buffer overflow|memory corruption|use-after-free|use after free|heap overflow|stack overflow|out-of-bounds|integer overflow)\b", re.I), "memory-corruption"),
    (re.compile(r"\b(information disclosure|sensitive information|information leak|credential leak)\b", re.I), "info-leak"),
    (re.compile(r"\b(cross-site request forgery|csrf)\b", re.I), "csrf"),
    (re.compile(r"\b(xml external entity|xxe)\b", re.I), "xxe"),
]

TYPE_ALIASES = {
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "rce",
    "code injection": "rce",
    "privesc": "privesc",
    "privilege escalation": "privesc",
    "lpe": "privesc",
    "elevation of privilege": "privesc",
    "sqli": "sqli",
    "sql injection": "sqli",
    "xss": "xss",
    "cross-site scripting": "xss",
    "auth-bypass": "auth-bypass",
    "auth bypass": "auth-bypass",
    "authentication bypass": "auth-bypass",
    "lfi": "lfi",
    "traversal": "lfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    "file read": "lfi",
    "file write": "lfi",
    "ssrf": "ssrf",
    "dos": "dos",
    "denial of service": "dos",
    "overflow": "memory-corruption",
    "buffer overflow": "memory-corruption",
    "memory-corruption": "memory-corruption",
    "uaf": "memory-corruption",
    "use-after-free": "memory-corruption",
    "info-leak": "info-leak",
    "information disclosure": "info-leak",
    "csrf": "csrf",
    "xxe": "xxe",
}

def normalize_vuln_type(type_query: str) -> str:
    """Normalize user input vulnerability type to canonical key."""
    if not type_query:
        return ""
    q = type_query.lower().strip()
    return TYPE_ALIASES.get(q, q)

def classify_vulnerability(cwe_ids: List[str], title: str, description: str) -> List[str]:
    """Classify CVE into zero or more standard vulnerability types."""
    types: Set[str] = set()
    
    # 1. Match from CWE IDs
    for cwe in cwe_ids:
        cwe_clean = cwe.strip().upper()
        if cwe_clean in CWE_MAP:
            types.add(CWE_MAP[cwe_clean])
            
    # 2. Match from text patterns
    combined_text = f"{title} {description}"
    for pattern, vtype in REGEX_PATTERNS:
        if pattern.search(combined_text):
            types.add(vtype)
            
    return sorted(list(types))
