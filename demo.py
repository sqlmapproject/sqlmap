#!/usr/bin/env python3
"""
Demo script to showcase the SQLMapCLI interface
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
import time

console = Console()

def demo_banner():
    """Display the banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗ ██████╗ ██╗     ███╗   ███╗ █████╗ ██████╗       ║
║   ██╔════╝██╔═══██╗██║     ████╗ ████║██╔══██╗██╔══██╗      ║
║   ███████╗██║   ██║██║     ██╔████╔██║███████║██████╔╝      ║
║   ╚════██║██║▄▄ ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝       ║
║   ███████║╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║           ║
║   ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝           ║
║                                                               ║
║              CLI - Automated SQL Injection Testing           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")
    console.print(
        Panel(
            "[yellow]⚠️  Legal Disclaimer: Only use on targets you have permission to test[/yellow]",
            border_style="yellow",
            box=box.ROUNDED
        )
    )
    console.print()

def demo_comprehensive_scan():
    """Demo comprehensive scan with results"""
    console.print(
        Panel(
            "[cyan]Running comprehensive scan on:[/cyan]\n[yellow]http://testphp.vulnweb.com/artists.php?artist=1[/yellow]",
            border_style="cyan",
            box=box.ROUNDED
        )
    )
    console.print()
    
    # Simulate scanning
    results_table = Table(title="Scan Results", box=box.ROUNDED)
    results_table.add_column("Level", style="cyan", justify="center")
    results_table.add_column("Risk", style="yellow", justify="center")
    results_table.add_column("Status", justify="center")
    results_table.add_column("Findings", style="magenta")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Scanning...", total=6)
        
        for level in range(1, 3):
            for risk in range(1, 4):
                progress.update(
                    task, 
                    description=f"[cyan]Testing Level {level}, Risk {risk}..."
                )
                time.sleep(0.5)  # Simulate work
                
                findings = "No vulnerabilities" if (level == 1 and risk == 1) else "2 found!" if level == 2 and risk == 3 else "No vulnerabilities"
                findings_style = "green" if findings == "No vulnerabilities" else "bold red"
                
                results_table.add_row(
                    str(level),
                    str(risk),
                    "[green]✓[/green]",
                    f"[{findings_style}]{findings}[/{findings_style}]"
                )
                
                progress.update(task, advance=1)
    
    console.print()
    console.print(results_table)
    console.print()

def demo_summary():
    """Demo result summary"""
    summary_text = """
[cyan]Target:[/cyan] http://testphp.vulnweb.com/artists.php?artist=1
[cyan]Total Tests:[/cyan] 6
[cyan]Duration:[/cyan] 45.32 seconds
[cyan]Vulnerabilities Found:[/cyan] 2
    """
    
    console.print(
        Panel(
            summary_text.strip(),
            title="[bold]Scan Summary[/bold]",
            border_style="red",
            box=box.DOUBLE
        )
    )
    console.print()
    
    # Display vulnerabilities
    vuln_table = Table(title="⚠️  Vulnerabilities Detected", box=box.HEAVY)
    vuln_table.add_column("Parameter", style="cyan")
    vuln_table.add_column("Type", style="yellow")
    vuln_table.add_column("Title", style="red")
    
    vuln_table.add_row(
        "artist",
        "boolean-based blind",
        "AND boolean-based blind - WHERE or HAVING clause"
    )
    vuln_table.add_row(
        "artist",
        "time-based blind",
        "MySQL >= 5.0.12 AND time-based blind (query SLEEP)"
    )
    
    console.print(vuln_table)
    console.print()
    console.print(
        "[bold red]⚠️  SQL injection vulnerabilities detected! Take immediate action.[/bold red]"
    )
    console.print()

if __name__ == "__main__":
    demo_banner()
    time.sleep(1)
    demo_comprehensive_scan()
    time.sleep(1)
    demo_summary()
