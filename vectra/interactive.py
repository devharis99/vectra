import shlex
import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.formatted_text import HTML
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vectra.search import search_cves, get_cve_by_id, get_database_stats
from vectra.gtfobins import search_gtfobins, list_gtfobins_functions, download_and_sync_gtfobins
from vectra.cli import print_cve_table, cmd_get, cmd_gtfo, cmd_stats

console = Console()

def render_banner():
    stats = get_database_stats()
    cve_count = f"{stats['total_cves']:,}"
    gtfo_bin_count = f"{stats['total_gtfo_binaries']:,}"
    gtfo_payload_count = f"{stats['total_gtfo_entries']:,}"
    sync_time = stats.get("last_sync", "Never")

    banner_art = f"""[bold red]
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
[/bold red]
[bold white on #1a0033]  ⚡ VECTRA - OFF-LINE VULNERABILITY & EXPLOITATION INTELLIGENCE ⚡  [/bold white on #1a0033]
[bold cyan]• CVE Records:[/bold cyan] [bold yellow]{cve_count}[/bold yellow]  │  [bold cyan]• GTFOBins:[/bold cyan] [bold yellow]{gtfo_payload_count} Payloads[/bold yellow] [dim]({gtfo_bin_count} binaries)[/dim]  │  [bold cyan]• Sync:[/bold cyan] [dim]{sync_time}[/dim]
[dim]Type [bold cyan]help[/bold cyan] for commands, [bold cyan]search <query>[/bold cyan], or [bold cyan]sudo <binary>[/bold cyan]. Type [bold red]exit[/bold red] to quit.[/dim]
"""
    console.print(banner_art)

def get_completer():
    vuln_types = ["rce", "privesc", "sqli", "xss", "auth-bypass", "lfi", "ssrf", "dos", "memory-corruption", "info-leak"]
    gtfo_funcs = list_gtfobins_functions() or ["sudo", "suid", "capabilities", "shell", "reverse-shell", "file-read", "file-write"]
    
    common_bins = {b: None for b in [
        "bash", "sh", "vim", "vi", "find", "python", "perl", "ruby", "awk", "sed",
        "tar", "zip", "less", "more", "curl", "wget", "nc", "nmap", "sudo", "docker",
        "systemctl", "journalctl", "cp", "mv", "chmod", "chown", "gdb", "php", "node"
    ]}

    nested_dict = {
        "search": {
            "--service": None,
            "--version": None,
            "--type": {t: None for t in vuln_types},
            "--severity": {"CRITICAL": None, "HIGH": None, "MEDIUM": None, "LOW": None},
            "--year": None,
            "--cwe": None,
            "--limit": None,
        },
        "s": None,
        "list": {
            "cves": None,
            "gtfo": None,
            "categories": None,
            "stats": None
        },
        "get": None,
        "info": None,
        "gtfo": common_bins,
        "gtfo-list": None,
        "sudo": common_bins,
        "suid": common_bins,
        "shell": common_bins,
        "rev": common_bins,
        "rce": None,
        "privesc": None,
        "sqli": None,
        "xss": None,
        "lfi": None,
        "auth": None,
        "ssrf": None,
        "dos": None,
        "stats": None,
        "sync-gtfo": None,
        "download": None,
        "help": None,
        "exit": None,
        "quit": None,
        "clear": None,
    }

    return NestedCompleter.from_nested_dict(nested_dict)

def show_help_panel():
    table = Table(
        title="⚡ VECTRA COMMAND CHEAT SHEET",
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_black",
        expand=True
    )
    table.add_column("Command / Shortcut", style="bold green", width=26, no_wrap=True)
    table.add_column("What it Does", style="white", ratio=1)
    table.add_column("Quick Example", style="bright_yellow", width=28)

    # CVE Search
    table.add_row(
        "search <query> / s <query>",
        "Search CVEs by software, version, or keywords",
        "search apache 2.4.49"
    )
    table.add_row(
        "<query>",
        "Direct search without typing 'search'",
        "openssh 8.2"
    )
    table.add_row(
        "rce <software>",
        "Filter for Remote Code Execution vulnerabilities",
        "rce tomcat"
    )
    table.add_row(
        "privesc <software>",
        "Filter for Privilege Escalation / LPE vulnerabilities",
        "privesc kernel"
    )
    table.add_row(
        "sqli <software>",
        "Filter for SQL Injection vulnerabilities",
        "sqli wordpress"
    )
    table.add_row(
        "auth <software>",
        "Filter for Authentication Bypass vulnerabilities",
        "auth pulse"
    )
    table.add_row(
        "lfi <software>",
        "Filter for Path Traversal / File Inclusion vulnerabilities",
        "lfi webmin"
    )
    table.add_row(
        "get <CVE-ID>",
        "Deep dive into CVE metrics, CVSS vector & patch links",
        "get CVE-2021-44228"
    )

    # GTFOBins
    table.add_row(
        "gtfo <binary> [type]",
        "Lookup Unix bypass & exploitation payloads",
        "gtfo find sudo"
    )
    table.add_row(
        "sudo <binary>",
        "Quick Sudo root privilege escalation payload",
        "sudo vim"
    )
    table.add_row(
        "suid <binary>",
        "Quick SUID root breakout payload",
        "suid bash"
    )
    table.add_row(
        "shell <binary>",
        "Payload to spawn an interactive shell",
        "shell find"
    )
    table.add_row(
        "rev <binary>",
        "Payload for reverse shell connection",
        "rev nc"
    )

    # Management
    table.add_row(
        "list [cves|gtfo|stats]",
        "Browse CVEs, GTFOBins payload index, or metrics",
        "list gtfo"
    )
    table.add_row(
        "stats",
        "Show severity breakdown & category totals",
        "stats"
    )
    table.add_row(
        "download / sync",
        "Download & sync official global CVE archive",
        "sync"
    )
    table.add_row(
        "clear / exit",
        "Clear terminal screen or terminate Vectra",
        "exit"
    )

    console.print(table)
    console.print("[dim]Tip: You can also run commands directly from bash via [bold cyan]vectra <command>[/bold cyan][/dim]\n")

def handle_search_command(args_list, forced_type=None):
    import argparse
    parser = argparse.ArgumentParser(prog="search", add_help=False)
    parser.add_argument("query", nargs="*", default=[])
    parser.add_argument("--service", "-s", default=None)
    parser.add_argument("--version", "-v", default=None)
    parser.add_argument("--type", "-t", default=forced_type)
    parser.add_argument("--severity", default=None)
    parser.add_argument("--min-score", type=float, default=None)
    parser.add_argument("--max-score", type=float, default=None)
    parser.add_argument("--year", "-y", type=int, default=None)
    parser.add_argument("--cwe", default=None)
    parser.add_argument("--limit", "-n", type=int, default=20)

    try:
        parsed = parser.parse_args(args_list)
    except Exception as e:
        console.print(f"[red]Invalid search syntax: {e}[/red]")
        return

    q_str = " ".join(parsed.query)
    vuln_type = forced_type if forced_type else parsed.type

    with console.status("[bold cyan]Querying FTS5 index...[/bold cyan]"):
        res = search_cves(
            query=q_str,
            service=parsed.service,
            version=parsed.version,
            vuln_type=vuln_type,
            severity=parsed.severity,
            min_score=parsed.min_score,
            max_score=parsed.max_score,
            year=parsed.year,
            cwe=parsed.cwe,
            limit=parsed.limit
        )

    filter_desc = []
    if q_str: filter_desc.append(f"'{q_str}'")
    if vuln_type: filter_desc.append(f"type: {vuln_type}")
    if parsed.service: filter_desc.append(f"service: {parsed.service}")
    if parsed.version: filter_desc.append(f"version: {parsed.version}")
    
    print_cve_table(res["results"], res["total"], " ".join(filter_desc) or "all")

def handle_list_command(args_list):
    sub = args_list[0].lower() if args_list else "all"

    if sub in ("stats", "summary"):
        cmd_stats(None)
    elif sub in ("gtfo", "bins", "binaries"):
        stats = get_database_stats()
        funcs = list_gtfobins_functions()
        results = search_gtfobins(query="", limit=100)
        binaries = sorted(list(set(r["binary"] for r in results)))
        
        info_text = (
            f"[bold]Total GTFOBins Payloads:[/bold] [bold yellow]{stats['total_gtfo_entries']:,}[/bold yellow] "
            f"across [bold cyan]{stats['total_gtfo_binaries']:,}[/bold cyan] binaries.\n\n"
            f"[bold]Exploit Categories:[/bold]\n" + ", ".join([f"[bold magenta]{f}[/bold magenta]" for f in funcs]) + "\n\n"
            f"[bold]Common Binaries (sample):[/bold]\n" + ", ".join([f"[cyan]{b}[/cyan]" for b in binaries[:40]]) + "..."
        )
        console.print(Panel(info_text, title="⚡ GTFOBins Payload Index", border_style="cyan", expand=True))
    elif sub in ("categories", "types", "functions"):
        funcs = list_gtfobins_functions()
        console.print(Panel(
            f"[bold]Available GTFOBins Categories:[/bold]\n" + ", ".join([f"[bold magenta]{f}[/bold magenta]" for f in funcs]),
            title="GTFOBins Categories", border_style="magenta", expand=True
        ))
    elif sub in ("cves", "all", ""):
        res = search_cves(query="", limit=25)
        print_cve_table(res["results"], res["total"], "latest indexed entries")
    else:
        res = search_cves(query=" ".join(args_list), limit=25)
        print_cve_table(res["results"], res["total"], " ".join(args_list))

def run_interactive_repl():
    render_banner()

    session = PromptSession()
    completer = get_completer()

    while True:
        try:
            prompt_html = HTML("<ansired><b>⚡ vectra</b></ansired><ansicyan>❯</ansicyan> ")
            user_input = session.prompt(prompt_html, completer=completer).strip()
            if not user_input:
                continue

            parts = shlex.split(user_input)
            cmd = parts[0].lower()
            cmd_args = parts[1:]

            if cmd in ("exit", "quit", "q"):
                console.print("[bold red]Session terminated. Happy hunting![/bold red]")
                break
            elif cmd in ("clear", "cls"):
                console.clear()
                render_banner()
            elif cmd in ("help", "?"):
                show_help_panel()
            elif cmd in ("list", "ls"):
                handle_list_command(cmd_args)
            elif cmd in ("search", "s", "find"):
                handle_search_command(cmd_args)
            elif cmd == "rce":
                handle_search_command(cmd_args, forced_type="rce")
            elif cmd in ("privesc", "lpe"):
                handle_search_command(cmd_args, forced_type="privesc")
            elif cmd == "sqli":
                handle_search_command(cmd_args, forced_type="sqli")
            elif cmd == "xss":
                handle_search_command(cmd_args, forced_type="xss")
            elif cmd in ("auth", "auth-bypass"):
                handle_search_command(cmd_args, forced_type="auth-bypass")
            elif cmd in ("lfi", "traversal"):
                handle_search_command(cmd_args, forced_type="lfi")
            elif cmd == "ssrf":
                handle_search_command(cmd_args, forced_type="ssrf")
            elif cmd == "dos":
                handle_search_command(cmd_args, forced_type="dos")
            elif cmd in ("get", "info", "show"):
                if not cmd_args:
                    console.print("[yellow]Usage: get <CVE-ID>[/yellow]")
                    continue
                class DummyArgs:
                    cve_id = cmd_args[0]
                cmd_get(DummyArgs())
            elif cmd == "gtfo":
                bin_name = cmd_args[0] if cmd_args else ""
                t_val = cmd_args[1] if len(cmd_args) > 1 else None
                class DummyGTFO:
                    binary = bin_name
                    type = t_val
                    limit = 20
                cmd_gtfo(DummyGTFO())
            elif cmd == "sudo":
                bin_name = cmd_args[0] if cmd_args else ""
                class DummySudo:
                    binary = bin_name
                    type = "sudo"
                    limit = 15
                cmd_gtfo(DummySudo())
            elif cmd == "suid":
                bin_name = cmd_args[0] if cmd_args else ""
                class DummySuid:
                    binary = bin_name
                    type = "suid"
                    limit = 15
                cmd_gtfo(DummySuid())
            elif cmd == "shell":
                bin_name = cmd_args[0] if cmd_args else ""
                class DummyShell:
                    binary = bin_name
                    type = "shell"
                    limit = 15
                cmd_gtfo(DummyShell())
            elif cmd in ("rev", "reverse-shell"):
                bin_name = cmd_args[0] if cmd_args else ""
                class DummyRev:
                    binary = bin_name
                    type = "reverse-shell"
                    limit = 15
                cmd_gtfo(DummyRev())
            elif cmd == "gtfo-list":
                cmd_gtfo_list(None)
            elif cmd == "stats":
                cmd_stats(None)
            elif cmd == "sync-gtfo":
                with console.status("[cyan]Syncing GTFOBins...[/cyan]"):
                    count = download_and_sync_gtfobins()
                console.print(f"[green]✓ Successfully synced {count:,} GTFOBins exploitation methods![/green]")
                completer = get_completer()
            elif cmd in ("sync", "download"):
                from vectra.cli import cmd_download
                class DummyDL:
                    force = False
                    limit = None
                    gtfo_only = False
                cmd_download(DummyDL())
            elif cmd.startswith("cve-"):
                class DummyArgs:
                    cve_id = cmd
                cmd_get(DummyArgs())
            else:
                handle_search_command([user_input])

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold red]Session ended.[/bold red]")
            break
        except Exception as ex:
            console.print(f"[bold red]Error:[/bold red] {ex}")
