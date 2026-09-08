"""
vectra.interactive — The REPL shell for Vectra.
prompt_toolkit and rich are imported LAZILY (inside run_interactive_repl) so
non-interactive CLI invocations like `vectra search foo` don't pay the 1.6s
prompt_toolkit import cost.
"""
import shlex
import sys


def _show_welcome_wizard(console, stats):
    """Show a beginner-friendly setup wizard when the DB is empty."""
    from rich.panel import Panel
    from rich.text import Text

    total_cves = stats.get("total_cves", 0)
    total_gtfo = stats.get("total_gtfo_entries", 0)

    if total_cves == 0 and total_gtfo == 0:
        console.print(Panel(
            "[bold white]👋 Welcome to VECTRA! Your database is empty.[/bold white]\n\n"
            "[dim]To get started, choose one of these options:[/dim]\n\n"
            "  [bold cyan]update[/bold cyan]          → Download everything (CVEs + GTFOBins) — takes a few minutes\n"
            "  [bold cyan]update --delta[/bold cyan]  → Quick daily delta update (a few MB, much faster)\n"
            "  [bold cyan]help[/bold cyan]            → See all available commands\n\n"
            "[dim]Recommended for first-time setup: type [bold cyan]update[/bold cyan] and press Enter.[/dim]",
            title="⚡ VECTRA — First Run Setup",
            border_style="bright_yellow",
            expand=True
        ))
        return True  # wizard shown

    if total_cves == 0:
        console.print(
            "[yellow]CVE database is empty.[/yellow] "
            "Run [bold cyan]update[/bold cyan] to download all CVEs.\n"
        )
    if total_gtfo == 0:
        console.print(
            "[yellow]GTFOBins database is empty.[/yellow] "
            "Run [bold cyan]update --gtfo-only[/bold cyan] to sync exploitation data.\n"
        )
    return False


def render_banner(console, stats):
    """Render the ASCII banner with live DB stats."""
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
    from prompt_toolkit.completion import NestedCompleter
    from vectra.gtfobins import list_gtfobins_functions

    vuln_types = ["rce", "privesc", "sqli", "xss", "auth-bypass", "lfi", "ssrf", "dos", "memory-corruption", "info-leak"]
    gtfo_funcs = list_gtfobins_functions() or ["sudo", "suid", "capabilities", "shell", "reverse-shell", "file-read", "file-write"]

    common_bins = {b: None for b in [
        "bash", "sh", "vim", "vi", "find", "python", "perl", "ruby", "awk", "sed",
        "tar", "zip", "less", "more", "curl", "wget", "nc", "nmap", "sudo", "docker",
        "systemctl", "journalctl", "cp", "mv", "chmod", "chown", "gdb", "php", "node"
    ]}

    nested_dict = {
        "search": {
            "--service": None, "--version": None,
            "--type": {t: None for t in vuln_types},
            "--severity": {"CRITICAL": None, "HIGH": None, "MEDIUM": None, "LOW": None},
            "--year": None, "--cwe": None, "--limit": None, "--details": None, "-d": None,
        },
        "s": None,
        "list": {"cves": None, "gtfo": None, "categories": None, "stats": None},
        "get": None,
        "info": None,
        "gtfo": common_bins,
        "gtfo-list": None,
        "sudo": common_bins,
        "suid": common_bins,
        "shell": common_bins,
        "rev": common_bins,
        "rce": None, "privesc": None, "sqli": None, "xss": None,
        "lfi": None, "auth": None, "ssrf": None, "dos": None,
        "stats": None,
        "sync-gtfo": None,
        "update": {
            "--check": None, "-c": None,
            "--delta": None, "-d": None,
            "--force": None,
            "--gtfo-only": None,
        },
        "download": {
            "--check": None, "-c": None,
            "--delta": None, "-d": None,
            "--force": None,
            "--gtfo-only": None,
        },
        "sync": None,
        "help": None,
        "exit": None, "quit": None, "clear": None,
    }

    return NestedCompleter.from_nested_dict(nested_dict)


def show_help_panel(console):
    from rich.table import Table
    from rich.panel import Panel

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

    # ── Quick Start ──
    table.add_row("[bold white]── QUICK START ──[/bold white]", "", "")
    table.add_row("update", "Download CVEs + GTFOBins (first run)", "update")
    table.add_row("update --delta", "Quick daily update (few MB)", "update --delta")
    table.add_row("update --check", "See if updates are available", "update --check")

    # ── CVE Search ──
    table.add_row("[bold white]── FINDING VULNERABILITIES ──[/bold white]", "", "")
    table.add_row("search <query>  /  s", "Search CVEs by software, version, or keywords", "search apache 2.4.49")
    table.add_row("<query>", "Direct search — just type and press Enter", "openssh 8.2")
    table.add_row("get <CVE-ID>", "Full CVE details, CVSS score, exploit steps", "get CVE-2021-44228")
    table.add_row("rce <software>", "Remote Code Execution CVEs only", "rce tomcat")
    table.add_row("privesc <software>", "Privilege Escalation CVEs only", "privesc kernel")
    table.add_row("sqli <software>", "SQL Injection CVEs only", "sqli wordpress")
    table.add_row("auth <software>", "Authentication Bypass CVEs only", "auth pulse")
    table.add_row("lfi <software>", "Path Traversal / File Inclusion CVEs", "lfi webmin")
    table.add_row("xss / ssrf / dos", "Filter by exploit category", "xss drupal")

    # ── GTFOBins ──
    table.add_row("[bold white]── GTFOBINS (Unix Bypass) ──[/bold white]", "", "")
    table.add_row("gtfo <binary>", "All GTFOBins techniques for a binary", "gtfo find")
    table.add_row("sudo <binary>", "Sudo privilege escalation steps", "sudo nmap")
    table.add_row("suid <binary>", "SUID root breakout payload", "suid bash")
    table.add_row("shell <binary>", "Spawn a shell via this binary", "shell find")
    table.add_row("rev <binary>", "Reverse shell payload", "rev nc")
    table.add_row("gtfo-list", "List all GTFOBins categories & stats", "gtfo-list")

    # ── Database ──
    table.add_row("[bold white]── DATABASE ──[/bold white]", "", "")
    table.add_row("stats", "Severity breakdown & category totals", "stats")
    table.add_row("list [cves|gtfo|stats]", "Browse CVEs, GTFOBins, or metrics", "list gtfo")
    table.add_row("update --gtfo-only", "Sync GTFOBins only", "update --gtfo-only")

    # ── Navigation ──
    table.add_row("[bold white]── NAVIGATION ──[/bold white]", "", "")
    table.add_row("clear", "Clear the screen", "clear")
    table.add_row("exit / quit", "Quit Vectra", "exit")

    console.print(table)
    console.print(
        "[dim]💡 Tip: Don't know what to type? Try: [bold cyan]rce apache[/bold cyan] or [bold cyan]gtfo bash[/bold cyan]\n"
        "    You can also run any command directly: [bold cyan]vectra search log4j[/bold cyan][/dim]\n"
    )


def handle_search_command(console, args_list, forced_type=None):
    import argparse as _argparse
    from vectra.search import search_cves
    from vectra.cli import print_cve_table, print_cve_card

    parser = _argparse.ArgumentParser(prog="search", add_help=False)
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
    parser.add_argument("--details", "-d", action="store_true", default=False)

    try:
        parsed = parser.parse_args(args_list)
    except Exception as e:
        console.print(f"[red]Invalid search syntax: {e}[/red]")
        console.print("[dim]Usage: search <keyword> [--type rce] [--severity HIGH] [--limit 10] [-d][/dim]")
        return

    q_str = " ".join(parsed.query)
    vuln_type = forced_type if forced_type else parsed.type

    if q_str:
        console.print(f"[dim]Searching CVEs for [bold cyan]{q_str}[/bold cyan]...[/dim]")

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

    results = res["results"]
    if not results:
        console.print(f"[yellow]No CVEs found matching: {q_str or 'criteria'}[/yellow]")
        console.print(
            "[dim]Try a broader term, check your spelling, or run "
            "[bold cyan]update --delta[/bold cyan] to fetch the latest CVEs.[/dim]"
        )
        return

    filter_desc = []
    if q_str: filter_desc.append(f"'{q_str}'")
    if vuln_type: filter_desc.append(f"type: {vuln_type}")
    if parsed.service: filter_desc.append(f"service: {parsed.service}")
    if parsed.version: filter_desc.append(f"version: {parsed.version}")
    query_title = " ".join(filter_desc) or "all"

    if parsed.details or len(results) <= 3:
        console.print(f"\n[bold green]⚡ VECTRA Vulnerability Intelligence ({len(results)} matches for {query_title}):[/bold green]\n")
        for r in results:
            print_cve_card(r)
    else:
        print_cve_table(results, res["total"], query_title)


def handle_list_command(console, args_list):
    from vectra.search import search_cves, get_database_stats
    from vectra.gtfobins import search_gtfobins, list_gtfobins_functions
    from vectra.cli import print_cve_table, cmd_stats
    from rich.panel import Panel

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
            "[bold]Available GTFOBins Categories:[/bold]\n" + ", ".join([f"[bold magenta]{f}[/bold magenta]" for f in funcs]),
            title="GTFOBins Categories", border_style="magenta", expand=True
        ))
    elif sub in ("cves", "all", ""):
        res = search_cves(query="", limit=25)
        from vectra.cli import print_cve_table
        print_cve_table(res["results"], res["total"], "latest indexed entries")
    else:
        res = search_cves(query=" ".join(args_list), limit=25)
        from vectra.cli import print_cve_table
        print_cve_table(res["results"], res["total"], " ".join(args_list))


def _make_prompt_text(stats):
    """Build a context-aware prompt showing live DB stats."""
    from prompt_toolkit.formatted_text import HTML
    cves = stats.get("total_cves", 0)
    gtfo = stats.get("total_gtfo_entries", 0)
    if cves > 0 or gtfo > 0:
        cve_str = f"{cves:,} CVEs" if cves > 0 else "No CVEs"
        gtfo_str = f"{gtfo:,} GTFOBins" if gtfo > 0 else "No GTFOBins"
        ctx = f"<ansibrightblack>[{cve_str} | {gtfo_str}]</ansibrightblack>"
    else:
        ctx = "<ansiyellow>[empty — type: update]</ansiyellow>"
    return HTML(f"<ansired><b>⚡ vectra</b></ansired><ansicyan>❯</ansicyan> {ctx} ")


def run_interactive_repl():
    # Heavy imports — only paid when user actually starts interactive mode
    from prompt_toolkit import PromptSession
    from prompt_toolkit.formatted_text import HTML
    from rich.console import Console
    from vectra.search import get_database_stats
    from vectra.cli import cmd_get, cmd_gtfo, cmd_stats, cmd_gtfo_list

    console = Console()

    # Load stats once for banner + prompt context
    stats = get_database_stats()

    render_banner(console, stats)
    _show_welcome_wizard(console, stats)

    session = PromptSession()
    completer = get_completer()

    while True:
        # Refresh stats for prompt context periodically (on each loop)
        try:
            stats = get_database_stats()
        except Exception:
            pass
        prompt_text = _make_prompt_text(stats)

        try:
            user_input = session.prompt(prompt_text, completer=completer).strip()
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
                stats = get_database_stats()
                render_banner(console, stats)

            elif cmd in ("help", "?"):
                show_help_panel(console)

            elif cmd in ("list", "ls"):
                handle_list_command(console, cmd_args)

            elif cmd in ("search", "s", "find"):
                handle_search_command(console, cmd_args)

            elif cmd == "rce":
                handle_search_command(console, cmd_args, forced_type="rce")
            elif cmd in ("privesc", "lpe"):
                handle_search_command(console, cmd_args, forced_type="privesc")
            elif cmd == "sqli":
                handle_search_command(console, cmd_args, forced_type="sqli")
            elif cmd == "xss":
                handle_search_command(console, cmd_args, forced_type="xss")
            elif cmd in ("auth", "auth-bypass"):
                handle_search_command(console, cmd_args, forced_type="auth-bypass")
            elif cmd in ("lfi", "traversal"):
                handle_search_command(console, cmd_args, forced_type="lfi")
            elif cmd == "ssrf":
                handle_search_command(console, cmd_args, forced_type="ssrf")
            elif cmd == "dos":
                handle_search_command(console, cmd_args, forced_type="dos")

            elif cmd in ("get", "info", "show"):
                if not cmd_args:
                    console.print("[yellow]Usage: get <CVE-ID>[/yellow]  [dim]e.g. get CVE-2021-44228[/dim]")
                    continue
                class _DummyArgs:
                    cve_id = cmd_args[0]
                cmd_get(_DummyArgs())

            elif cmd == "gtfo":
                bin_name = cmd_args[0] if cmd_args else ""
                t_val = cmd_args[1] if len(cmd_args) > 1 else None
                class _DummyGTFO:
                    binary = bin_name
                    type = t_val
                    limit = 20
                cmd_gtfo(_DummyGTFO())

            elif cmd == "sudo":
                bin_name = cmd_args[0] if cmd_args else ""
                if not bin_name:
                    console.print("[yellow]Usage: sudo <binary>[/yellow]  [dim]e.g. sudo nmap[/dim]")
                    continue
                class _DummySudo:
                    binary = bin_name
                    type = "sudo"
                    limit = 15
                cmd_gtfo(_DummySudo())

            elif cmd == "suid":
                bin_name = cmd_args[0] if cmd_args else ""
                if not bin_name:
                    console.print("[yellow]Usage: suid <binary>[/yellow]  [dim]e.g. suid bash[/dim]")
                    continue
                class _DummySuid:
                    binary = bin_name
                    type = "suid"
                    limit = 15
                cmd_gtfo(_DummySuid())

            elif cmd == "shell":
                bin_name = cmd_args[0] if cmd_args else ""
                if not bin_name:
                    console.print("[yellow]Usage: shell <binary>[/yellow]  [dim]e.g. shell find[/dim]")
                    continue
                class _DummyShell:
                    binary = bin_name
                    type = "shell"
                    limit = 15
                cmd_gtfo(_DummyShell())

            elif cmd in ("rev", "reverse-shell"):
                bin_name = cmd_args[0] if cmd_args else ""
                if not bin_name:
                    console.print("[yellow]Usage: rev <binary>[/yellow]  [dim]e.g. rev nc[/dim]")
                    continue
                class _DummyRev:
                    binary = bin_name
                    type = "reverse-shell"
                    limit = 15
                cmd_gtfo(_DummyRev())

            elif cmd == "gtfo-list":
                cmd_gtfo_list(None)

            elif cmd == "stats":
                cmd_stats(None)

            elif cmd == "sync-gtfo":
                from vectra.gtfobins import download_and_sync_gtfobins
                with console.status("[cyan]Syncing GTFOBins...[/cyan]"):
                    count = download_and_sync_gtfobins(force=True)
                console.print(f"[green]✓ Successfully synced {count:,} GTFOBins exploitation methods![/green]")
                completer = get_completer()

            elif cmd in ("sync", "download", "update", "up"):
                from vectra.cli import cmd_download

                class _DummyDL:
                    check = any(arg in ("--check", "-c", "check") for arg in cmd_args)
                    delta = any(arg in ("--delta", "-d", "delta") for arg in cmd_args)
                    force = any(arg in ("--force", "-f", "force") for arg in cmd_args)
                    limit = None
                    gtfo_only = any(arg in ("--gtfo-only", "gtfo") for arg in cmd_args)

                cmd_download(_DummyDL())

            elif cmd.upper().startswith("CVE-"):
                class _DummyArgs:
                    cve_id = cmd
                cmd_get(_DummyArgs())

            else:
                # Unknown command — treat as a search query with friendly feedback
                console.print(f"[dim]Searching CVEs for [bold cyan]{user_input}[/bold cyan]...[/dim]")
                handle_search_command(console, [user_input])

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold red]Session ended.[/bold red]")
            break
        except Exception as ex:
            console.print(f"[bold red]Error:[/bold red] {ex}")
            console.print("[dim]Type [bold cyan]help[/bold cyan] to see available commands.[/dim]")
