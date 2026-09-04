import sys
import argparse
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TransferSpeedColumn, DownloadColumn

from vectra.config import DB_PATH, DEFAULT_DATA_DIR
from vectra.db import init_db, get_db_connection
from vectra.search import search_cves, get_cve_by_id, get_database_stats
from vectra.gtfobins import search_gtfobins, download_and_sync_gtfobins, list_gtfobins_functions
from vectra.downloader import fetch_latest_release_info, download_file_with_progress, ingest_cve_zip
from vectra.exploit_guide import analyze_command_payload, get_cve_exploit_guide

console = Console()

def get_severity_style(severity: Optional[str], score: Optional[float]) -> Tuple[str, str]:
    s = (severity or "").upper()
    if s == "CRITICAL" or (score and score >= 9.0):
        return "bold white on #880000", "CRITICAL"
    elif s == "HIGH" or (score and score >= 7.0):
        return "bold black on #ff7700", "HIGH"
    elif s == "MEDIUM" or (score and score >= 4.0):
        return "bold black on #e6b800", "MEDIUM"
    elif s == "LOW":
        return "bold black on #00aa44", "LOW"
    return "dim", "N/A"

def format_score_meter(score: Optional[float], severity: Optional[str]) -> str:
    if score is None:
        return "[dim]--.-[/dim]"
    filled = max(0, min(10, int(round(score))))
    empty = 10 - filled
    if score >= 9.0:
        meter_color = "red"
    elif score >= 7.0:
        meter_color = "bright_red"
    elif score >= 4.0:
        meter_color = "yellow"
    else:
        meter_color = "green"
    
    return f"[{meter_color}]{'█' * filled}[dim]{'░' * empty}[/dim] {score:.1f}[/{meter_color}]"

def print_cve_card(r: Dict[str, Any]):
    """Print an enriched, detailed vulnerability card for a specific CVE."""
    cve_id = r["cve_id"]
    score = r.get("cvss_v3_score") or r.get("cvss_v2_score")
    score_meter = format_score_meter(score, r.get("cvss_v3_severity"))
    sev_style, sev_label = get_severity_style(r.get("cvss_v3_severity"), score)

    service = r.get("affected_products") or r.get("affected_vendors") or "Not Specified"
    versions = r.get("affected_versions") or "See technical description"
    types = r.get("vuln_types") or "Vulnerability"
    desc = r.get("description") or "No description provided."

    cve_guide = get_cve_exploit_guide(cve_id)

    card = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    card.add_row("[bold cyan]Service & Product:[/bold cyan]", f"[bold white]{service}[/bold white]")
    card.add_row("[bold cyan]Vulnerable Versions:[/bold cyan]", f"[bold yellow]{versions}[/bold yellow]")
    card.add_row("[bold cyan]Vulnerability Type:[/bold cyan]", f"[bold bright_magenta]{types.upper()}[/bold bright_magenta]")
    card.add_row("[bold cyan]Severity & Score:[/bold cyan]", f"[{sev_style}] {sev_label} [/{sev_style}]  {score_meter}")
    card.add_row("[bold cyan]Vulnerability Description:[/bold cyan]", desc)

    items = [card]

    if cve_guide:
        if cve_guide.get("how_to"):
            items.append(Text("\n🎯 How to Exploit / Reproduction Steps:", style="bold yellow"))
            items.append(Text(cve_guide["how_to"], style="bright_green"))
        if cve_guide.get("remediation"):
            items.append(Text(f"\n🛡️ Remediation: {cve_guide['remediation']}", style="dim"))

    refs = r.get("references") or []
    if refs:
        ref_text = " • ".join([f"[link={u}]{u}[/link]" for u in refs[:3]])
        items.append(Text.from_markup(f"\n[bold cyan]Advisories & Links:[/bold cyan] {ref_text}"))

    border_col = "bright_red" if sev_label in ("CRITICAL", "HIGH") else "cyan"
    panel = Panel(
        Group(*items),
        title=f"🔥 [bold bright_cyan]{cve_id}[/bold bright_cyan] - Service Vulnerability Intelligence",
        border_style=border_col,
        expand=True
    )
    console.print(panel)

def print_cve_table(results: list, total: int, query_desc: str):
    if not results:
        console.print(f"[yellow]No CVEs found matching: {query_desc}[/yellow]")
        return

    table = Table(
        title=f"⚡ VECTRA Intelligence ({len(results)} of {total:,} matches)",
        expand=True,
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black"
    )
    table.add_column("CVE ID", style="bold bright_cyan", width=16, no_wrap=True)
    table.add_column("CVSS Score", justify="left", width=18)
    table.add_column("Severity", justify="center", width=11)
    table.add_column("Type", style="bold bright_magenta", width=15)
    table.add_column("Service / Product", style="bright_green", width=22)
    table.add_column("Summary / Snippet", style="white", ratio=1)

    for r in results:
        score = r.get("cvss_v3_score") or r.get("cvss_v2_score")
        score_meter = format_score_meter(score, r.get("cvss_v3_severity"))
        sev_style, sev_label = get_severity_style(r.get("cvss_v3_severity"), score)
        
        types = r.get("vuln_types") or "-"
        products = r.get("affected_products") or r.get("affected_vendors") or "-"
        if len(products) > 28:
            products = products[:25] + "..."

        snippet = r.get("snippet_desc") or r.get("description") or ""
        snippet_clean = snippet.replace("\n", " ").strip()
        if len(snippet_clean) > 130:
            snippet_clean = snippet_clean[:127] + "..."

        table.add_row(
            r["cve_id"],
            score_meter,
            f"[{sev_style}] {sev_label} [/{sev_style}]",
            types,
            products,
            snippet_clean
        )

    console.print(table)
    console.print("[dim]Tip: Use [bold cyan]vectra get <CVE-ID>[/bold cyan] or [bold cyan]vectra search <query> -d[/bold cyan] for full vulnerability descriptions, affected versions, and exploit steps.[/dim]\n")

def cmd_search(args):
    """Execute CVE search from CLI."""
    query_parts = []
    if args.query:
        query_parts.append(f"'{args.query}'")
    if args.service:
        query_parts.append(f"service: {args.service}")
    if args.version:
        query_parts.append(f"version: {args.version}")
    if args.type:
        query_parts.append(f"type: {args.type}")
    if args.severity:
        query_parts.append(f"severity: {args.severity}")
    if args.cwe:
        query_parts.append(f"cwe: {args.cwe}")

    query_desc = " ".join(query_parts) if query_parts else "all"

    with console.status("[bold cyan]Searching local vulnerability database...[/bold cyan]"):
        res = search_cves(
            query=args.query or "",
            service=args.service,
            version=args.version,
            vuln_type=args.type,
            severity=args.severity,
            min_score=args.min_score,
            max_score=args.max_score,
            year=args.year,
            cwe=args.cwe,
            limit=args.limit
        )

    results = res["results"]
    if not results:
        console.print(f"[yellow]No CVEs found matching: {query_desc}[/yellow]")
        return

    # If results <= 3 or user asked for details, display full detailed vulnerability cards
    if getattr(args, "details", False) or len(results) <= 3:
        console.print(f"\n[bold green]⚡ VECTRA Vulnerability Breakdown ({len(results)} matches for {query_desc}):[/bold green]\n")
        for r in results:
            print_cve_card(r)
    else:
        print_cve_table(results, res["total"], query_desc)

def cmd_get(args):
    """Show comprehensive details for a specific CVE."""
    cve_id = args.cve_id.strip().upper()
    data = get_cve_by_id(cve_id)
    if not data:
        console.print(f"[bold red]CVE not found in local database:[/bold red] {cve_id}")
        return

    print_cve_card(data)

def cmd_gtfo(args):
    """Search and display GTFOBins exploits with rich descriptions, versions, and execution guides."""
    results = search_gtfobins(query=args.binary or "", function_type=args.type, limit=args.limit)
    if not results:
        console.print(f"[yellow]No GTFOBins exploits found for '{args.binary or ''}' (type: {args.type or 'any'})[/yellow]")
        return

    console.print(f"\n[bold green]⚡ GTFOBins Exploitation Vectors ({len(results)} found)[/bold green]\n")
    for r in results:
        b_name = r["binary"]
        f_name = r["function"]
        code_str = r.get("code", "")

        guide = analyze_command_payload(b_name, f_name, code_str, r.get("description", ""))
        func_badge = f"[bold white on red] {f_name.upper()} [/bold white on red]"
        bin_header = f"[bold bright_cyan]{b_name}[/bold bright_cyan]  {func_badge}  [dim]• {guide['technique_name']}[/dim]"

        body_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        body_table.add_row("[bold cyan]Technique / Name:[/bold cyan]", f"[bold white]{guide['technique_name']}[/bold white]")
        body_table.add_row("[bold cyan]Version Scope / Constraints:[/bold cyan]", f"[bold yellow]{guide['version_scope']}[/bold yellow]")
        
        # Description / Mechanism
        exploit_desc = r.get("description")
        if not exploit_desc or exploit_desc == f"[{f_name.upper()}]":
            exploit_desc = guide["mechanism"]
        body_table.add_row("[bold cyan]Exploit Mechanism:[/bold cyan]", exploit_desc)
        
        # Step-by-step How to execute
        body_table.add_row("[bold cyan]How to Execute:[/bold cyan]", f"[bright_green]{guide['how_to']}[/bright_green]")

        elements = [body_table]
        if code_str:
            code_syn = Syntax(code_str, "bash", theme="monokai", line_numbers=False, word_wrap=True)
            elements.append(Text("\n⚡ Command Payload:", style="bold cyan"))
            elements.append(code_syn)

        border_col = "bright_red" if f_name in ("sudo", "suid") else "cyan"
        console.print(Panel(
            Group(*elements),
            title=bin_header,
            subtitle=f"[link={r.get('url')}]{r.get('url')}[/link]",
            style="cyan",
            border_style=border_col,
            expand=True
        ))

def cmd_gtfo_list(args):
    """List GTFOBins categories and binary counts."""
    funcs = list_gtfobins_functions()
    stats = get_database_stats()
    console.print(Panel(
        f"[bold]Total Payloads:[/bold] [bold yellow]{stats['total_gtfo_entries']:,}[/bold yellow] across [bold cyan]{stats['total_gtfo_binaries']:,}[/bold cyan] binaries\n\n"
        f"[bold]Categories:[/bold] " + ", ".join([f"[bold magenta]{f}[/bold magenta]" for f in funcs]),
        title="⚡ GTFOBins Exploit Index", style="magenta", border_style="magenta", expand=True
    ))

def cmd_stats(args):
    """Show database statistics."""
    stats = get_database_stats()
    table = Table(title="⚡ VECTRA Intelligence Metrics", show_header=False, box=None, expand=True)
    table.add_row("[bold cyan]Total CVE Records:[/bold cyan]", f"[bold white]{stats['total_cves']:,}[/bold white]")
    table.add_row("[bold green]GTFOBins Payloads:[/bold green]", f"[bold yellow]{stats['total_gtfo_entries']:,}[/bold yellow] across [bold white]{stats['total_gtfo_binaries']:,}[/bold white] binaries")
    table.add_row("[bold yellow]Last Dataset Sync:[/bold yellow]", f"{stats['last_sync']}")
    console.print(Panel(table, style="cyan", border_style="cyan", expand=True))

    if stats["severity_distribution"]:
        sev_table = Table(title="Severity Breakdown", show_header=True, header_style="bold yellow", expand=True)
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        for k, v in stats["severity_distribution"].items():
            style, _ = get_severity_style(k, None)
            sev_table.add_row(f"[{style}] {k} [/{style}]", f"{v:,}")
        console.print(sev_table)

    if stats["top_vulnerability_types"]:
        vt_table = Table(title="Top Vulnerability Categories", show_header=True, header_style="bold magenta", expand=True)
        vt_table.add_column("Category")
        vt_table.add_column("Count", justify="right")
        for k, v in stats["top_vulnerability_types"].items():
            vt_table.add_row(f"[bold magenta]{k}[/bold magenta]", f"{v:,}")
        console.print(vt_table)

def cmd_download(args):
    """Download and sync official CVE archive and GTFOBins."""
    init_db()

    # 1. Sync GTFOBins
    console.print("[bold cyan]=== Step 1: Syncing GTFOBins Exploitation Database ===[/bold cyan]")
    with console.status("[cyan]Downloading & indexing GTFOBins recipes...[/cyan]"):
        try:
            count = download_and_sync_gtfobins()
            console.print(f"[green]✓ Successfully indexed {count:,} GTFOBins exploitation methods![/green]\n")
        except Exception as e:
            console.print(f"[red]Failed to sync GTFOBins: {e}[/red]\n")

    if args.gtfo_only:
        return

    # 2. Download and index CVEs
    console.print("[bold cyan]=== Step 2: Official CVE List v5 Ingestion ===[/bold cyan]")
    with console.status("[cyan]Checking latest CVEProject/cvelistV5 release...[/cyan]"):
        rel_info = fetch_latest_release_info()

    zip_url = rel_info.get("full_zip_url")
    tag = rel_info.get("tag_name")
    console.print(f"[bold]Latest Release Tag:[/bold] {tag}")
    if not zip_url:
        console.print("[red]Could not determine download URL for CVE dataset.[/red]")
        return

    dest_zip = DEFAULT_DATA_DIR / f"cvelist_{tag}.zip"
    if not dest_zip.exists() or args.force:
        console.print(f"[cyan]Downloading full CVE archive ({rel_info.get('full_zip_size', 0)/(1024*1024):.1f} MB)...[/cyan]")
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task("Downloading CVE archive...", total=rel_info.get("full_zip_size") or 100)
            
            def cb(downloaded, total, speed):
                progress.update(task_id, completed=downloaded, total=total)

            download_file_with_progress(zip_url, dest_zip, progress_callback=cb)
            console.print("[green]✓ Download complete![/green]")
    else:
        console.print(f"[yellow]Using cached archive: {dest_zip.name}[/yellow]")

    # Ingest and index
    console.print(f"[cyan]Indexing CVE JSON records directly into SQLite FTS5 database...[/cyan]")
    max_rec = args.limit if args.limit else None
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} records"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task("Indexing CVEs...", total=1000)

        def index_cb(current, total, current_cve):
            progress.update(task_id, completed=current, total=total, description=f"Indexing: {current_cve}")

        total_indexed = ingest_cve_zip(dest_zip, max_records=max_rec, progress_callback=index_cb)

    console.print(f"\n[bold green]✓ Successfully indexed {total_indexed:,} CVEs into local database![/bold green]")

def cmd_interactive(args):
    """Launch interactive terminal REPL."""
    from vectra.interactive import run_interactive_repl
    run_interactive_repl()

def main():
    parser = argparse.ArgumentParser(
        prog="vectra",
        description="⚡ VECTRA: High-Performance Local CVE & GTFOBins Intelligence Search Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vectra                            Launch interactive red terminal shell
  vectra search "apache 2.4.49"     Search vulnerabilities by service and version
  vectra search --type rce          Search all Remote Code Execution CVEs
  vectra gtfo find -t sudo          Find Sudo privilege escalation for 'find'
  vectra get CVE-2021-44228         Inspect detailed CVE breakdown and advisories
  vectra stats                      Show database metrics and severity breakdown
  vectra download                   Download & sync full official CVE list (386,000+ records)
        """
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # search
    p_search = subparsers.add_parser("search", aliases=["s", "find"], help="Search CVEs by service, version, or keywords")
    p_search.add_argument("query", nargs="?", default="", help="Keywords, service, or version (e.g. 'apache 2.4.49', 'log4j')")
    p_search.add_argument("--service", "-s", help="Filter by software service name")
    p_search.add_argument("--version", "-v", help="Filter by software version")
    p_search.add_argument("--type", "-t", help="Vulnerability category (rce, privesc, sqli, xss, auth-bypass, lfi, ssrf, dos)")
    p_search.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Filter by CVSS severity")
    p_search.add_argument("--min-score", type=float, help="Minimum CVSS v3 score (e.g. 7.0)")
    p_search.add_argument("--max-score", type=float, help="Maximum CVSS v3 score (e.g. 10.0)")
    p_search.add_argument("--year", "-y", type=int, help="Filter by year (e.g. 2024)")
    p_search.add_argument("--cwe", help="Filter by CWE ID (e.g. CWE-89)")
    p_search.add_argument("--limit", "-n", type=int, default=25, help="Max results (default: 25)")
    p_search.add_argument("--details", "-d", action="store_true", help="Show full vulnerability card and exploit walkthrough")
    p_search.set_defaults(func=cmd_search)

    # get
    p_get = subparsers.add_parser("get", aliases=["info", "show"], help="Show full technical details of a CVE ID")
    p_get.add_argument("cve_id", help="CVE identifier (e.g. CVE-2021-44228)")
    p_get.set_defaults(func=cmd_get)

    # gtfo
    p_gtfo = subparsers.add_parser("gtfo", aliases=["bins"], help="Search GTFOBins Unix bypass and escalation payloads")
    p_gtfo.add_argument("binary", nargs="?", default="", help="Binary name (e.g. vim, find, bash, sudo, python)")
    p_gtfo.add_argument("--type", "-t", help="Exploit type (sudo, suid, capabilities, shell, reverse-shell, file-read, file-write)")
    p_gtfo.add_argument("--limit", "-n", type=int, default=20, help="Max results (default: 20)")
    p_gtfo.set_defaults(func=cmd_gtfo)

    # gtfo-list
    p_gtfo_list = subparsers.add_parser("gtfo-list", help="List all GTFOBins exploit categories & metrics")
    p_gtfo_list.set_defaults(func=cmd_gtfo_list)

    # stats
    p_stats = subparsers.add_parser("stats", help="Display local database metrics and severity breakdown")
    p_stats.set_defaults(func=cmd_stats)

    # download
    p_dl = subparsers.add_parser("download", aliases=["sync", "update"], help="Download and index official CVEs and GTFOBins")
    p_dl.add_argument("--force", "-f", action="store_true", help="Force re-download even if archive exists")
    p_dl.add_argument("--limit", type=int, help="Limit number of CVEs to index")
    p_dl.add_argument("--gtfo-only", action="store_true", help="Only sync GTFOBins database")
    p_dl.set_defaults(func=cmd_download)

    # interactive
    p_repl = subparsers.add_parser("interactive", aliases=["i", "tui", "repl"], help="Start interactive red terminal shell")
    p_repl.set_defaults(func=cmd_interactive)

    args = parser.parse_args()
    if not args.command:
        cmd_interactive(args)
    else:
        args.func(args)

if __name__ == "__main__":
    main()
