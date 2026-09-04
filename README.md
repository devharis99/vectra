# ⚡ VECTRA: Offline CVE & GTFOBins Intelligence Search Engine

**VECTRA** is a fast, offline-capable terminal vulnerability and exploitation search engine designed for penetration testers, security researchers, and CTF players.

```
██▒   █▓▓█████  ▄████▄  ████████▓ ██▀███   ▄▄▄      
▓██░   █▒▓█   ▀ ▒██▀ ▀█  ╚══██╔══╝▓██ ▒ ██▒▒████▄    
 ▓██  █▒░▒███   ▒▓█    ▄    ██║   ▓██ ░▄█ ▒▒██  ▀█▄  
  ▒██ █░░▒▓█  ▄ ▒▓▓▄ ▄██▒   ██║   ▒██▀▀█▄  ░██▄▄▄▄██ 
   ▒▀█░  ░▒████▒▒ ▓███▀ ░   ██║   ░██▓ ▒██▒ ▓█   ▓██▒
   ░ ▐░  ░░ ▒░ ░░ ░▒ ▒  ░   ╚═╝   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░
   ░ ░░   ░ ░  ░  ░  ▒              ░▒ ░ ▒░  ▒   ▒▒ ░
     ░░     ░   ░                 ░░   ░   ░   ▒    
      ░     ░  ░░ ░                             ░  ░ 
     ░          ░                                    
```

## Features

- **Blazingly Fast SQLite FTS5**: Sub-millisecond BM25 ranking across **25,000+ indexed CVEs** and official historical records.
- **Service & Version Matching**: Direct search by service and version (e.g. `apache 2.4.49`, `openssh 8.2p1`, `vsftpd 2.3.4`).
- **Vulnerability Category Filtering**: Filter by `rce`, `privesc`, `sqli`, `auth`, `lfi`, `ssrf`, `dos`, `xss`.
- **GTFOBins Exploit Payloads**: **3,608 privilege escalation payloads** across **458 Unix binaries** (Sudo, SUID, Shell, Reverse Shell, File Read/Write).
- **Interactive Terminal REPL**: Full-color cyber UI with tab-completion and responsive code rendering.
- **Docker Support**: Self-contained CLI and REST API container configurations.

---

## Quick Start

### Global Terminal Usage
```bash
# Launch interactive red terminal shell
vectra

# Search CVEs by software and version
vectra search "apache 2.4.49"
vectra search --type rce

# GTFOBins exploits
vectra gtfo find -t sudo
vectra gtfo vim -t suid

# Deep dive into a CVE
vectra get CVE-2021-44228

# Display database metrics
vectra stats
```

---

## Interactive Shell Commands

Inside `vectra`, use any of the quick shortcuts:

| Command | What it Does | Example |
| :--- | :--- | :--- |
| `search <query>` / `s <query>` | Search CVEs by software or version | `search apache 2.4.49` |
| `<query>` | Direct search without typing 'search' | `openssh 8.2` |
| `rce <software>` | Filter for Remote Code Execution | `rce tomcat` |
| `privesc <software>` | Filter for Privilege Escalation / LPE | `privesc kernel` |
| `sqli <software>` | Filter for SQL Injection | `sqli wordpress` |
| `auth <software>` | Filter for Authentication Bypass | `auth pulse` |
| `lfi <software>` | Filter for Path Traversal / File Inclusion | `lfi webmin` |
| `get <CVE-ID>` | Deep dive into CVE metrics & patch links | `get CVE-2021-44228` |
| `gtfo <binary> [type]` | Lookup Unix bypass & exploitation payloads | `gtfo find sudo` |
| `sudo <binary>` | Sudo root privilege escalation payload | `sudo vim` |
| `suid <binary>` | SUID root breakout payload | `suid bash` |
| `shell <binary>` | Interactive shell breakout payload | `shell find` |
| `rev <binary>` | Reverse shell payload | `rev nc` |
| `list [cves\|gtfo\|stats]` | Browse CVEs, GTFOBins index, or metrics | `list gtfo` |
| `stats` | Show severity breakdown & category totals | `stats` |
| `download` / `sync` | Sync official global CVE archive | `sync` |
| `help` | Show command cheat sheet | `help` |
| `clear` / `exit` | Clear screen or quit Vectra | `exit` |

---

## Docker Setup

### Run CLI via Docker:
```bash
docker compose run --rm vectra-cli
```

### Run REST API Service:
```bash
docker compose up -d vectra-api
# API available at http://127.0.0.1:8000
```

---

## License & Attribution

Built with official datasets from `CVEProject/cvelistV5` and `GTFOBins/GTFOBins.github.io`.
