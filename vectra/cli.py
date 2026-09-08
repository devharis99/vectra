"""
vectra.cli — All heavy imports are LAZY (inside functions) so `vectra search foo`
starts in ~300ms instead of ~3 seconds.
"""
import sys
import argparse
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List


# ─── Lazy helpers ─────────────────────────────────────────────────────────────

def _console():
    from rich.console import Console
    return Console()

_con = None
def console():
    global _con
    if _con is None:
        from rich.console import Console
        _con = Console()
    return _con


# ─── Display helpers ──────────────────────────────────────────────────────────

def format_date(date_val: Optional[str]) -> str:
    """Format ISO timestamp or date string into clean YYYY-MM-DD."""
    if not date_val:
        return "N/A"
    d_str = str(date_val).strip()
    if "T" in d_str:
        return d_str.split("T")[0]
    if len(d_str) >= 10 and d_str[4] == "-" and d_str[7] == "-":
        return d_str[:10]
    return d_str or "N/A"

def format_version_specs(r: Dict[str, Any]) -> str:
    """Generate precise, human-readable affected version specifications."""
    from vectra.exploit_guide import get_cve_exploit_guide
    version_details = r.get("version_details") or []
    specs = []

    if isinstance(version_details, list) and version_details:
        for item in version_details:
            if not isinstance(item, dict):
                continue
            v = str(item.get("version", "")).strip()
            lt = str(item.get("lessThan", "")).strip()
            status = str(item.get("status", "")).lower()

            if status == "unaffected":
                continue

            if lt:
                if v and v.lower() not in ("0", "*", "n/a", "unspecified", "all"):
                    specs.append(f">= {v}, < {lt}")
                else:
                    specs.append(f"< {lt}")
            elif v and v.lower() not in ("0", "*", "n/a", "unspecified", "all"):
                specs.append(f"= {v}")

        seen = set()
        deduped = []
        for s in specs:
            if s not in seen:
                seen.add(s)
                deduped.append(s)
        if deduped:
            res_str = ", ".join(deduped[:6])
            if len(deduped) > 6:
                res_str += f" (+{len(deduped) - 6} more)"
            return res_str

    aff_ver = r.get("affected_versions")
    if aff_ver and aff_ver.strip():
        parts = [p.strip() for p in aff_ver.split() if p.strip()]
        if len(parts) > 6:
            return ", ".join(parts[:6]) + f" (+{len(parts) - 6} more)"
        return ", ".join(parts)

    cve_id = r.get("cve_id", "")
    guide = get_cve_exploit_guide(cve_id)
    if guide and guide.get("service"):
        return guide["service"]

    return "See technical description"

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


# ─── CVE card / table ─────────────────────────────────────────────────────────

def print_cve_card(r: Dict[str, Any]):
    """Print an enriched, detailed vulnerability card for a specific CVE."""
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.syntax import Syntax
    from rich.console import Group
    from vectra.exploit_guide import get_cve_exploit_guide

    cve_id = r["cve_id"]
    score = r.get("cvss_v3_score") or r.get("cvss_v2_score")
    score_meter = format_score_meter(score, r.get("cvss_v3_severity"))
    sev_style, sev_label = get_severity_style(r.get("cvss_v3_severity"), score)

    service = r.get("affected_products") or r.get("affected_vendors") or "Not Specified"
    versions = format_version_specs(r)
    types = r.get("vuln_types") or "Vulnerability"
    desc = r.get("description") or "No description provided."
    pub_date = format_date(r.get("date_published"))
    upd_date = format_date(r.get("date_updated"))

    cve_guide = get_cve_exploit_guide(cve_id)

    card = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    card.add_column("Key", style="bold cyan", width=24)
    card.add_column("Value", style="white")

    card.add_row("Service & Product:", f"[bold white]{service}[/bold white]")
    card.add_row("Vulnerable Versions:", f"[bold yellow]{versions}[/bold yellow]")
    card.add_row("Vulnerability Type:", f"[bold bright_magenta]{types.upper()}[/bold bright_magenta]")
    card.add_row("Severity & Score:", f"[{sev_style}] {sev_label} [/{sev_style}]  {score_meter}")

    date_str = f"[bold white]{pub_date}[/bold white]"
    if upd_date and upd_date != "N/A" and upd_date != pub_date:
        date_str += f"  [dim](Updated: {upd_date})[/dim]"
    card.add_row("Published / Updated:", date_str)
    card.add_row("Vulnerability Description:", desc)

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
    console().print(panel)

def print_cve_table(results: list, total: int, query_desc: str):
    from rich.table import Table
    if not results:
        console().print(f"[yellow]No CVEs found matching: {query_desc}[/yellow]")
        console().print(
            "[dim]Try a broader term, or run [bold cyan]update --delta[/bold cyan] to fetch the latest CVEs.[/dim]"
        )
        return

    table = Table(
        title=f"⚡ VECTRA Intelligence ({len(results)} of {total:,} matches)",
        expand=True,
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black"
    )
    table.add_column("CVE ID", style="bold bright_cyan", width=16, no_wrap=True)
    table.add_column("Published", style="cyan", width=12, justify="center")
    table.add_column("CVSS Score", justify="left", width=18)
    table.add_column("Severity", justify="center", width=11)
    table.add_column("Type", style="bold bright_magenta", width=14)
    table.add_column("Service & Version", style="bright_green", width=26)
    table.add_column("Summary / Snippet", style="white", ratio=1)

    for r in results:
        score = r.get("cvss_v3_score") or r.get("cvss_v2_score")
        score_meter = format_score_meter(score, r.get("cvss_v3_severity"))
        sev_style, sev_label = get_severity_style(r.get("cvss_v3_severity"), score)

        pub_date = format_date(r.get("date_published"))
        if pub_date == "N/A" and r.get("year"):
            pub_date = str(r.get("year"))

        types = r.get("vuln_types") or "-"
        products = r.get("affected_products") or r.get("affected_vendors") or "-"
        ver = format_version_specs(r)
        if ver and ver != "See technical description":
            ver_short = (ver[:14] + "...") if len(ver) > 16 else ver
            if products != "-":
                svc_disp = f"{products} [bold yellow]({ver_short})[/bold yellow]"
            else:
                svc_disp = f"[bold yellow]{ver_short}[/bold yellow]"
        else:
            svc_disp = products

        if len(svc_disp) > 36:
            svc_disp = svc_disp[:33] + "..."

        snippet = r.get("snippet_desc") or r.get("description") or ""
        snippet_clean = snippet.replace("\n", " ").strip()
        if len(snippet_clean) > 120:
            snippet_clean = snippet_clean[:117] + "..."

        table.add_row(
            r["cve_id"],
            pub_date,
            score_meter,
            f"[{sev_style}] {sev_label} [/{sev_style}]",
            types,
            svc_disp,
            snippet_clean
        )

    console().print(table)
    console().print(
        "[dim]Tip: Use [bold cyan]vectra get <CVE-ID>[/bold cyan] or add [bold cyan]-d[/bold cyan] "
        "to your search for full descriptions, affected versions, and exploit steps.[/dim]\n"
    )


# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_search(args):
    """Execute CVE search from CLI."""
    from vectra.search import search_cves

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

    with console().status("[bold cyan]Searching local vulnerability database...[/bold cyan]"):
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
        console().print(f"[yellow]No CVEs found matching: {query_desc}[/yellow]")
        console().print(
            "[dim]Try a different keyword, or run [bold cyan]update --delta[/bold cyan] to fetch new CVEs.[/dim]"
        )
        return

    if getattr(args, "details", False) or len(results) <= 3:
        console().print(f"\n[bold green]⚡ VECTRA Vulnerability Breakdown ({len(results)} matches for {query_desc}):[/bold green]\n")
        for r in results:
            print_cve_card(r)
    else:
        print_cve_table(results, res["total"], query_desc)

def cmd_get(args):
    """Show comprehensive details for a specific CVE."""
    from vectra.search import get_cve_by_id
    cve_id = args.cve_id.strip().upper()
    data = get_cve_by_id(cve_id)
    if not data:
        console().print(f"[bold red]CVE not found in local database:[/bold red] {cve_id}")
        console().print(
            "[dim]If this is a recent CVE, run [bold cyan]vectra update --delta[/bold cyan] to fetch the latest.[/dim]"
        )
        return
    print_cve_card(data)

def cmd_gtfo(args):
    """Search and display GTFOBins exploits with rich descriptions, versions, and execution guides."""
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.syntax import Syntax
    from rich.console import Group
    from vectra.gtfobins import search_gtfobins, list_gtfobins_functions
    from vectra.exploit_guide import analyze_command_payload
    from vectra.search import get_database_stats

    results = search_gtfobins(query=args.binary or "", function_type=args.type, limit=args.limit)
    if not results:
        # Beginner-friendly empty state
        stats = get_database_stats()
        total = stats.get("total_gtfo_entries", 0)
        if total == 0:
            console().print(
                "[yellow]GTFOBins database is empty.[/yellow]\n"
                "[dim]Run [bold cyan]vectra update --gtfo-only[/bold cyan] to download GTFOBins exploitation data.[/dim]"
            )
        else:
            funcs = list_gtfobins_functions()
            sample_bins = ["bash", "find", "vim", "python", "perl", "awk", "curl", "nmap", "tar"]
            console().print(
                f"[yellow]No GTFOBins entries found for '{args.binary or ''}' (type: {args.type or 'any'})[/yellow]\n"
                f"[dim]Try one of these: [bold cyan]{', '.join(sample_bins[:6])}[/bold cyan]\n"
                f"Available types: [bold magenta]{', '.join(funcs[:8])}[/bold magenta][/dim]"
            )
        return

    console().print(f"\n[bold green]⚡ GTFOBins Exploitation Vectors ({len(results)} found)[/bold green]\n")
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

        exploit_desc = r.get("description")
        if not exploit_desc or exploit_desc == f"[{f_name.upper()}]":
            exploit_desc = guide["mechanism"]
        body_table.add_row("[bold cyan]Exploit Mechanism:[/bold cyan]", exploit_desc)
        body_table.add_row("[bold cyan]How to Execute:[/bold cyan]", f"[bright_green]{guide['how_to']}[/bright_green]")

        date_added = r.get("date_added") or "Indexed"
        body_table.add_row("[bold cyan]Database Sync / Added:[/bold cyan]", f"[bold white]{date_added}[/bold white]")

        elements = [body_table]
        if code_str:
            code_syn = Syntax(code_str, "bash", theme="monokai", line_numbers=False, word_wrap=True)
            elements.append(Text("\n⚡ Command Payload:", style="bold cyan"))
            elements.append(code_syn)

        border_col = "bright_red" if f_name in ("sudo", "suid") else "cyan"
        console().print(Panel(
            Group(*elements),
            title=bin_header,
            subtitle=f"[link={r.get('url')}]{r.get('url')}[/link]",
            style="cyan",
            border_style=border_col,
            expand=True
        ))

def cmd_gtfo_list(args):
    """List GTFOBins categories and binary counts."""
    from rich.panel import Panel
    from vectra.gtfobins import list_gtfobins_functions
    from vectra.search import get_database_stats

    funcs = list_gtfobins_functions()
    stats = get_database_stats()
    last_sync = stats.get("last_sync", "Never")
    # Prefer the more specific GTFOBins sync timestamp if available
    from vectra.db import get_db_connection, get_metadata
    try:
        conn = get_db_connection()
        gtfo_sync = get_metadata(conn, "gtfobins_last_sync")
        conn.close()
        if gtfo_sync:
            last_sync = gtfo_sync
    except Exception:
        pass

    console().print(Panel(
        f"[bold]Total Payloads:[/bold] [bold yellow]{stats['total_gtfo_entries']:,}[/bold yellow] across [bold cyan]{stats['total_gtfo_binaries']:,}[/bold cyan] binaries\n"
        f"[bold]Last GTFOBins Sync:[/bold] [dim]{last_sync}[/dim]\n\n"
        f"[bold]Categories:[/bold] " + ", ".join([f"[bold magenta]{f}[/bold magenta]" for f in funcs]),
        title="⚡ GTFOBins Exploit Index", style="magenta", border_style="magenta", expand=True
    ))

def cmd_stats(args):
    """Show database statistics."""
    from rich.table import Table
    from rich.panel import Panel
    from vectra.search import get_database_stats

    stats = get_database_stats()
    table = Table(title="⚡ VECTRA Intelligence Metrics", show_header=False, box=None, expand=True)
    table.add_row("[bold cyan]Total CVE Records:[/bold cyan]", f"[bold white]{stats['total_cves']:,}[/bold white]")
    table.add_row("[bold green]GTFOBins Payloads:[/bold green]", f"[bold yellow]{stats['total_gtfo_entries']:,}[/bold yellow] across [bold white]{stats['total_gtfo_binaries']:,}[/bold white] binaries")
    table.add_row("[bold yellow]Last Dataset Sync:[/bold yellow]", f"{stats['last_sync']}")
    table.add_row("[bold magenta]CVE Release Tag:[/bold magenta]", f"{stats.get('release_tag', 'N/A')}")
    console().print(Panel(table, style="cyan", border_style="cyan", expand=True))

    if stats["severity_distribution"]:
        sev_table = Table(title="Severity Breakdown", show_header=True, header_style="bold yellow", expand=True)
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        for k, v in stats["severity_distribution"].items():
            style, _ = get_severity_style(k, None)
            sev_table.add_row(f"[{style}] {k} [/{style}]", f"{v:,}")
        console().print(sev_table)

    if stats["top_vulnerability_types"]:
        vt_table = Table(title="Top Vulnerability Categories", show_header=True, header_style="bold magenta", expand=True)
        vt_table.add_column("Category")
        vt_table.add_column("Count", justify="right")
        for k, v in stats["top_vulnerability_types"].items():
            vt_table.add_row(f"[bold magenta]{k}[/bold magenta]", f"{v:,}")
        console().print(vt_table)

def cmd_download(args):
    """Download, update, or check official CVE dataset and GTFOBins."""
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.console import Group
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TransferSpeedColumn, DownloadColumn
    from vectra.db import init_db
    from vectra.downloader import fetch_latest_release_info, download_file_with_progress, ingest_cve_zip, check_cve_updates
    from vectra.gtfobins import download_and_sync_gtfobins, check_gtfobins_updates
    from vectra.config import DEFAULT_DATA_DIR

    init_db()

    # ── --check: show status of both CVEs and GTFOBins ──
    if getattr(args, "check", False):
        console().print("[bold cyan]=== VECTRA Intelligence Update Status Check ===[/bold cyan]\n")

        with console().status("[cyan]Checking CVE upstream release...[/cyan]"):
            cve_status = check_cve_updates()

        with console().status("[cyan]Checking GTFOBins upstream ETag...[/cyan]"):
            gtfo_status = check_gtfobins_updates()

        # CVE status table
        check_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        check_table.add_column("Key", style="bold cyan", width=30)
        check_table.add_column("Value", style="white")

        if cve_status.get("error"):
            check_table.add_row("⚠️  CVE Check Error:", f"[red]{cve_status['error']}[/red]")
        else:
            check_table.add_row("Local Indexed CVEs:", f"[bold yellow]{cve_status['total_cves']:,}[/bold yellow]")
            check_table.add_row("Local CVE Release Tag:", f"[bold white]{cve_status['current_tag']}[/bold white]")
            check_table.add_row("Last CVE Sync:", f"[dim]{cve_status['last_sync']}[/dim]")
            check_table.add_row("", "")
            check_table.add_row("Upstream CVE Release Tag:", f"[bold green]{cve_status['latest_tag']}[/bold green]")
            check_table.add_row("Upstream Release Published:", f"[dim]{format_date(cve_status.get('published_at'))}[/dim]")
            full_mb = cve_status.get("full_zip_size", 0) / (1024 * 1024)
            delta_mb = cve_status.get("delta_zip_size", 0) / (1024 * 1024)
            if delta_mb > 0:
                check_table.add_row("Daily Delta Size:", f"[bright_yellow]{delta_mb:.1f} MB (Fast update)[/bright_yellow]")
            if full_mb > 0:
                check_table.add_row("Full Archive Size:", f"[white]{full_mb:.1f} MB (386,000+ records)[/white]")

        check_table.add_row("", "")

        # GTFOBins status
        if gtfo_status.get("error"):
            check_table.add_row("⚠️  GTFOBins Check Error:", f"[red]{gtfo_status['error']}[/red]")
        else:
            check_table.add_row("Local GTFOBins Entries:", f"[bold yellow]{gtfo_status['total_entries']:,}[/bold yellow]")
            check_table.add_row("Last GTFOBins Sync:", f"[dim]{gtfo_status['last_sync']}[/dim]")
            gtfo_upd = "[bold bright_yellow]⚡ Update available[/bold bright_yellow]" if gtfo_status["has_updates"] else "[bold green]✓ Up to date[/bold green]"
            check_table.add_row("GTFOBins Status:", gtfo_upd)

        items = [check_table]

        cve_needs_update = not cve_status.get("error") and cve_status.get("has_updates", False)
        gtfo_needs_update = not gtfo_status.get("error") and gtfo_status.get("has_updates", False)

        if cve_needs_update or gtfo_needs_update:
            parts = []
            if cve_needs_update:
                parts.append(
                    "  • Fast CVE update:   [bold cyan]vectra update --delta[/bold cyan]\n"
                    "  • Full CVE sync:      [bold cyan]vectra update[/bold cyan]"
                )
            if gtfo_needs_update:
                parts.append("  • GTFOBins update:   [bold cyan]vectra update --gtfo-only[/bold cyan]")
            status_text = (
                "\n[bold bright_yellow]⚡ UPDATES AVAILABLE![/bold bright_yellow] Run one of:\n"
                + "\n".join(parts)
            )
            border_style = "bright_yellow"
        else:
            status_text = "\n[bold green]✓ Everything is up to date![/bold green]"
            border_style = "green"

        items.append(Text.from_markup(status_text))
        console().print(Panel(
            Group(*items),
            title="⚡ VECTRA Database Status & Update Center",
            border_style=border_style,
            expand=True
        ))
        return

    # ── GTFOBins sync (always runs unless --gtfo-only skips CVEs) ──
    force = getattr(args, "force", False)
    gtfo_only = getattr(args, "gtfo_only", False)

    console().print("[bold cyan]=== Step 1: Syncing GTFOBins Exploitation Database ===[/bold cyan]")
    with console().status("[cyan]Checking GTFOBins upstream for changes...[/cyan]"):
        try:
            status_msgs = []
            count = download_and_sync_gtfobins(force=force, callback=lambda m: status_msgs.append(m))
            if any("already up-to-date" in m for m in status_msgs):
                console().print(f"[green]✓ GTFOBins: {count:,} exploitation methods indexed ([dim]already up-to-date[/dim]).[/green]\n")
            else:
                console().print(f"[green]✓ GTFOBins: {count:,} exploitation methods indexed![/green]\n")
        except Exception as e:
            console().print(f"[red]Failed to sync GTFOBins: {e}[/red]\n")

    if gtfo_only:
        return

    # ── CVE sync ──
    is_delta = getattr(args, "delta", False)
    if is_delta:
        console().print("[bold cyan]=== Step 2: Ingesting Daily Delta CVEs (Fast Update) ===[/bold cyan]")
    else:
        console().print("[bold cyan]=== Step 2: Official Global CVE List v5 Ingestion ===[/bold cyan]")

    with console().status("[cyan]Checking latest CVEProject/cvelistV5 release info...[/cyan]"):
        rel_info = fetch_latest_release_info()

    tag = rel_info.get("tag_name")
    if not tag:
        console().print("[red]Could not determine latest CVEProject release tag.[/red]")
        return

    if is_delta:
        zip_url = rel_info.get("delta_zip_url")
        zip_size = rel_info.get("delta_zip_size", 0)
        dest_zip = DEFAULT_DATA_DIR / f"cvelist_delta_{tag}.zip"
        mode_label = "Daily delta archive"
    else:
        zip_url = rel_info.get("full_zip_url")
        zip_size = rel_info.get("full_zip_size", 0)
        dest_zip = DEFAULT_DATA_DIR / f"cvelist_{tag}.zip"
        mode_label = "Full global archive"

    console().print(f"[bold]Target Release Tag:[/bold] {tag} ({mode_label})")
    if not zip_url:
        console().print(f"[red]Could not determine download URL for {mode_label.lower()}.[/red]")
        return

    if not dest_zip.exists() or force:
        console().print(f"[cyan]Downloading {mode_label.lower()} ({zip_size/(1024*1024):.1f} MB)...[/cyan]")
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console()
        ) as progress:
            task_id = progress.add_task(f"Downloading {mode_label}...", total=zip_size or 100)

            def cb(downloaded, total, speed):
                progress.update(task_id, completed=downloaded, total=total)

            download_file_with_progress(zip_url, dest_zip, progress_callback=cb)
            console().print("[green]✓ Download complete![/green]")
    else:
        console().print(f"[yellow]Using cached archive: {dest_zip.name}[/yellow]")

    console().print("[cyan]Indexing CVE JSON records directly into SQLite FTS5 database...[/cyan]")
    max_rec = args.limit if getattr(args, "limit", None) else None

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} records"),
        TimeRemainingColumn(),
        console=console()
    ) as progress:
        task_id = progress.add_task("Indexing CVEs...", total=1000)

        def index_cb(current, total, current_cve):
            progress.update(task_id, completed=current, total=total, description=f"Indexing: {current_cve}")

        total_indexed = ingest_cve_zip(dest_zip, max_records=max_rec, progress_callback=index_cb, release_tag=tag)

    if is_delta:
        console().print(f"\n[bold green]✓ Successfully updated {total_indexed:,} delta CVEs in local database![/bold green]")
    else:
        console().print(f"\n[bold green]✓ Successfully indexed {total_indexed:,} CVEs into local database![/bold green]")

def cmd_interactive(args):
    """Launch interactive terminal REPL."""
    from vectra.interactive import run_interactive_repl
    run_interactive_repl()


# ─── CLI entry point ──────────────────────────────────────────────────────────

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
  vectra update --check             Check if new CVE releases are available upstream
  vectra update --delta             Quick update: fetch today's new & modified delta CVEs
  vectra update                     Download & sync full official CVE list (386,000+ records)
  vectra update --gtfo-only         Re-sync GTFOBins exploitation database only
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

    # update / download
    for cmd_name, cmd_alias in [("update", ["up"]), ("download", ["sync"])]:
        p_up = subparsers.add_parser(cmd_name, aliases=cmd_alias, help="Update or download official CVEs and GTFOBins")
        p_up.add_argument("--check", "-c", action="store_true", help="Check for new CVE + GTFOBins updates without downloading")
        p_up.add_argument("--delta", "-d", action="store_true", help="Quick update: download and index only latest daily delta CVEs")
        p_up.add_argument("--force", "-f", action="store_true", help="Force re-download even if archive exists or GTFOBins ETag matches")
        p_up.add_argument("--limit", type=int, help="Limit number of CVEs to index")
        p_up.add_argument("--gtfo-only", action="store_true", help="Only sync GTFOBins database")
        p_up.set_defaults(func=cmd_download)

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
