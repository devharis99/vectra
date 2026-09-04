import tempfile
from pathlib import Path
from vectra.vuln_classifier import classify_vulnerability, normalize_vuln_type
from vectra.search import extract_service_and_version, search_cves, get_cve_by_id
from vectra.parser import parse_cve_v5
from vectra.db import init_db, get_db_connection, save_cves_batch, save_gtfobins_batch
from vectra.gtfobins import search_gtfobins

def test_vuln_classifier():
    # Test RCE
    assert "rce" in classify_vulnerability(["CWE-94"], "Remote code execution in Spring", "Allows RCE")
    # Test PrivEsc
    assert "privesc" in classify_vulnerability(["CWE-269"], "Baron Samedit heap overflow", "Local privilege escalation in Sudo")
    # Test SQLi
    assert "sqli" in classify_vulnerability(["CWE-89"], "Auth bypass via SQL injection", "vulnerable parameter")
    # Test LFI
    assert "lfi" in classify_vulnerability(["CWE-22"], "Path traversal in Apache HTTP Server", "Arbitrary file read")

def test_service_and_version_extraction():
    srv, ver = extract_service_and_version("apache 2.4.49")
    assert srv == "apache"
    assert ver == "2.4.49"

    srv, ver = extract_service_and_version("openssh 8.2p1")
    assert srv == "openssh"
    assert ver == "8.2p1"

def test_gtfobins_search():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = Path(tmpdir) / "test.db"
        init_db(test_db)
        conn = get_db_connection(test_db)

        sample_entries = [
            {"binary": "find", "function": "sudo", "description": "Execute root shell", "code": "sudo find . -exec /bin/sh \\; -quit", "url": "https://gtfobins.github.io/gtfobins/find/"},
            {"binary": "vim", "function": "suid", "description": "Spawn SUID shell", "code": "./vim -c ':!/bin/sh'", "url": "https://gtfobins.github.io/gtfobins/vim/"}
        ]
        save_gtfobins_batch(conn, sample_entries)

        res_find = search_gtfobins(query="find", conn=conn)
        assert len(res_find) == 1
        assert res_find[0]["binary"] == "find"

        res_sudo = search_gtfobins(function_type="sudo", conn=conn)
        assert len(res_sudo) == 1
        assert res_sudo[0]["function"] == "sudo"

        conn.close()

def test_cve_ingestion_and_search():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = Path(tmpdir) / "test.db"
        init_db(test_db)
        conn = get_db_connection(test_db)

        sample_cve_json = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": "CVE-2021-41773",
                "state": "PUBLISHED",
                "datePublished": "2021-10-05T00:00:00.000Z"
            },
            "containers": {
                "cna": {
                    "title": "Apache HTTP Server 2.4.49 Path Traversal and RCE",
                    "descriptions": [
                        {"lang": "en", "value": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root and achieve remote code execution."}
                    ],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ],
                    "problemTypes": [
                        {"descriptions": [{"cweId": "CWE-22"}]}
                    ],
                    "affected": [
                        {
                            "vendor": "Apache Software Foundation",
                            "product": "Apache HTTP Server",
                            "versions": [{"version": "2.4.49", "status": "affected"}]
                        }
                    ]
                }
            }
        }

        parsed = parse_cve_v5(sample_cve_json)
        assert parsed["cve_id"] == "CVE-2021-41773"
        assert parsed["cvss_v3_score"] == 9.8
        assert parsed["cvss_v3_severity"] == "CRITICAL"
        assert "rce" in parsed["vuln_types"]
        assert "lfi" in parsed["vuln_types"]

        save_cves_batch(conn, [parsed])

        # Test search by service and version
        res = search_cves(query="apache 2.4.49", conn=conn)
        assert res["total"] == 1
        assert res["results"][0]["cve_id"] == "CVE-2021-41773"

        # Test search by vuln type
        res_rce = search_cves(vuln_type="rce", conn=conn)
        assert res_rce["total"] == 1

        # Test search by severity
        res_crit = search_cves(severity="CRITICAL", conn=conn)
        assert res_crit["total"] == 1

        conn.close()

if __name__ == "__main__":
    test_vuln_classifier()
    test_service_and_version_extraction()
    test_gtfobins_search()
    test_cve_ingestion_and_search()
    print("All core engine unit tests passed successfully!")
