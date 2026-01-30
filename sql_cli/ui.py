from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from typing import List, Dict
from .models import ScanResult

console = Console()


def print_banner():
    """Display a beautiful banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗ ██████╗ ██╗     ███╗   ███╗ █████╗ ██████╗         ║
║   ██╔════╝██╔═══██╗██║     ████╗ ████║██╔══██╗██╔══██╗        ║
║   ███████╗██║   ██║██║     ██╔████╔██║███████║██████╔╝        ║
║   ╚════██║██║▄▄ ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝         ║
║   ███████║╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║             ║
║   ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝             ║
║                                                               ║
║              CLI - Automated SQL Injection Testing            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")
    console.print(
        Panel(
            "[yellow]⚠️  Legal Disclaimer: Only use on targets you have permission to test[/yellow]",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )
    console.print()


def display_summary(results: ScanResult):
    """Display a comprehensive summary of results"""
    console.print()

    # Calculate duration
    duration = 0.0
    if results["end_time"] and results["start_time"]:
        duration = (results["end_time"] - results["start_time"]).total_seconds()

    # Create summary panel
    summary_text = f"""
[cyan]Target:[/cyan] {results["target"] or "N/A"}
[cyan]Total Tests:[/cyan] {results["total_tests"]}
[cyan]Duration:[/cyan] {duration:.2f} seconds
[cyan]Vulnerabilities Found:[/cyan] {len(results["vulnerabilities"])}
    """

    console.print(
        Panel(
            summary_text.strip(),
            title="[bold]Scan Summary[/bold]",
            border_style="green" if len(results["vulnerabilities"]) == 0 else "red",
            box=box.DOUBLE,
        )
    )

    # Display vulnerabilities if found
    if results["vulnerabilities"]:
        console.print()
        vuln_table = Table(title="⚠️  Vulnerabilities Detected", box=box.HEAVY)
        vuln_table.add_column("Parameter", style="cyan")
        vuln_table.add_column("Type", style="yellow")
        vuln_table.add_column("Title", style="red")

        for vuln in results["vulnerabilities"]:
            vuln_table.add_row(
                vuln.get("parameter", "N/A"),
                vuln.get("type", "N/A"),
                vuln.get("title", "N/A"),
            )

        console.print(vuln_table)
        console.print()
        console.print(
            "[bold red]⚠️  SQL injection vulnerabilities detected! Take immediate action.[/bold red]"
        )
    else:
        console.print()
        console.print(
            "[bold green]✓ No SQL injection vulnerabilities detected.[/bold green]"
        )

    console.print()


def display_batch_results(results: List[Dict]):
    """Display batch scan results in a table"""
    console.print()

    # Create results table
    results_table = Table(title="Batch Scan Results", box=box.ROUNDED)
    results_table.add_column("URL", style="cyan", no_wrap=False)
    results_table.add_column("Status", justify="center")
    results_table.add_column("Vulnerabilities", style="magenta")

    vulnerable_count = 0
    successful_count = 0

    for result in results:
        url = result["url"][:60] + "..." if len(result["url"]) > 60 else result["url"]

        if result.get("error"):
            status = "[red]✗ Error[/red]"
            vulns = f"[red]{result['error'][:40]}[/red]"
        elif result["success"]:
            successful_count += 1
            if result["is_vulnerable"]:
                vulnerable_count += 1
                status = "[red]✓ Vulnerable[/red]"
                vulns = f"[red]{len(result['vulnerabilities'])} found[/red]"
            else:
                status = "[green]✓ Clean[/green]"
                vulns = "[green]None[/green]"
        else:
            status = "[yellow]✗ Failed[/yellow]"
            vulns = "[yellow]N/A[/yellow]"

        results_table.add_row(url, status, vulns)

    console.print(results_table)

    # Summary
    console.print()
    summary = f"""
[cyan]Batch Summary:[/cyan]
  Total Endpoints: {len(results)}
  Successful Scans: {successful_count}
  Vulnerable: [red]{vulnerable_count}[/red]
  Clean: [green]{successful_count - vulnerable_count}[/green]
    """

    border_color = "red" if vulnerable_count > 0 else "green"
    console.print(
        Panel(
            summary.strip(),
            title="[bold]Summary[/bold]",
            border_style=border_color,
            box=box.DOUBLE,
        )
    )
    console.print()
