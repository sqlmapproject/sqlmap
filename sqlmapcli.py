#!/usr/bin/env python3
"""
SQLMap CLI - A beautiful CLI wrapper for sqlmap
Automates comprehensive SQL injection testing with a single command
"""

import subprocess
import sys
import argparse
import time
import re
from pathlib import Path
from typing import List, Dict, Tuple
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich import box
    from rich.style import Style
except ImportError:
    print("Error: 'rich' library is required. Install it with: pip install rich")
    sys.exit(1)

console = Console()

SQLMAP_PATH = Path(__file__).parent / "sqlmap.py"

# SQL injection techniques
TECHNIQUES = {
    'B': 'Boolean-based blind',
    'E': 'Error-based',
    'U': 'Union query-based',
    'S': 'Stacked queries',
    'T': 'Time-based blind',
    'Q': 'Inline queries'
}

class SQLMapCLI:
    def __init__(self):
        self.console = Console()
        self.results = {
            'total_tests': 0,
            'vulnerabilities': [],
            'start_time': None,
            'end_time': None,
            'target': None
        }
    
    def print_banner(self):
        """Display a beautiful banner"""
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
        self.console.print(banner, style="bold cyan")
        self.console.print(
            Panel(
                "[yellow]⚠️  Legal Disclaimer: Only use on targets you have permission to test[/yellow]",
                border_style="yellow",
                box=box.ROUNDED
            )
        )
        self.console.print()
    
    def run_sqlmap_test(self, url: str, level: int, risk: int, technique: str = "BEUSTQ", 
                        batch: bool = True, data: str = None, verbose: int = 1, 
                        extra_args: List[str] = None) -> Tuple[bool, str]:
        """Run sqlmap with specified parameters"""
        cmd = [
            sys.executable,
            str(SQLMAP_PATH),
            "-u", url,
            f"--level={level}",
            f"--risk={risk}",
            f"--technique={technique}",
            "-v", str(verbose)
        ]
        
        if batch:
            cmd.append("--batch")
        
        if data:
            cmd.extend(["--data", data, "--method", "POST"])
        
        if extra_args:
            cmd.extend(extra_args)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout per test
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "Test timed out after 10 minutes"
        except Exception as e:
            return False, str(e)
    
    def parse_results(self, output: str) -> Dict:
        """Parse sqlmap output for vulnerabilities"""
        vulns = []
        
        # Look for vulnerability indicators
        if "sqlmap identified the following injection point" in output:
            # Extract injection details
            lines = output.split('\n')
            current_param = 'Unknown'  # Default parameter name
            
            for i, line in enumerate(lines):
                if "Parameter:" in line:
                    current_param = line.split("Parameter:")[1].strip()
                elif "Type:" in line:
                    vuln_type = line.split("Type:")[1].strip()
                    # Check if next line contains the title
                    if i + 1 < len(lines) and "Title:" in lines[i + 1]:
                        title = lines[i + 1].split("Title:")[1].strip()
                        vulns.append({
                            'parameter': current_param,
                            'type': vuln_type,
                            'title': title
                        })
        
        # Check for backend DBMS detection
        backend_dbms = None
        if "back-end DBMS:" in output.lower():
            for line in output.split('\n'):
                if "back-end DBMS:" in line.lower():
                    backend_dbms = line.split(":", 1)[1].strip()
                    break
        
        return {
            'vulnerabilities': vulns,
            'backend_dbms': backend_dbms,
            'is_vulnerable': len(vulns) > 0 or "vulnerable" in output.lower()
        }
    
    def comprehensive_scan(self, url: str, max_level: int = 5, max_risk: int = 3, 
                          techniques: str = "BEUSTQ", data: str = None, verbose: int = 1):
        """Run comprehensive scan with all levels and risks"""
        self.results['target'] = url
        self.results['start_time'] = datetime.now()
        
        # Create results table
        results_table = Table(title="Scan Results", box=box.ROUNDED)
        results_table.add_column("Level", style="cyan", justify="center")
        results_table.add_column("Risk", style="yellow", justify="center")
        results_table.add_column("Status", justify="center")
        results_table.add_column("Findings", style="magenta")
        
        total_tests = max_level * max_risk
        test_count = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            overall_task = progress.add_task(
                f"[cyan]Scanning {url}...", 
                total=total_tests
            )
            
            for level in range(1, max_level + 1):
                for risk in range(1, max_risk + 1):
                    test_count += 1
                    
                    progress.update(
                        overall_task, 
                        description=f"[cyan]Testing Level {level}, Risk {risk}..."
                    )
                    
                    success, output = self.run_sqlmap_test(url, level, risk, techniques, data=data, verbose=verbose)
                    parsed = self.parse_results(output)
                    
                    status = "✓" if success else "✗"
                    status_style = "green" if success else "red"
                    
                    findings = "No vulnerabilities" if not parsed['is_vulnerable'] else f"{len(parsed['vulnerabilities'])} found!"
                    findings_style = "green" if not parsed['is_vulnerable'] else "bold red"
                    
                    if parsed['is_vulnerable']:
                        self.results['vulnerabilities'].extend(parsed['vulnerabilities'])
                    
                    results_table.add_row(
                        str(level),
                        str(risk),
                        f"[{status_style}]{status}[/{status_style}]",
                        f"[{findings_style}]{findings}[/{findings_style}]"
                    )
                    
                    progress.update(overall_task, advance=1)
                    self.results['total_tests'] += 1
        
        self.results['end_time'] = datetime.now()
        
        # Display results
        self.console.print()
        self.console.print(results_table)
        self.display_summary()
    
    def quick_scan(self, url: str, level: int = 1, risk: int = 1, data: str = None, 
                   raw: bool = False, verbose: int = 1):
        """Run a quick scan with default settings"""
        self.results['target'] = url
        self.results['start_time'] = datetime.now()
        
        if not raw:
            scan_info = f"[cyan]Running quick scan on:[/cyan]\n[yellow]{url}[/yellow]\n[dim]Level: {level}, Risk: {risk}[/dim]"
            if data:
                scan_info += f"\n[dim]POST Data: {data}[/dim]"
            
            self.console.print(
                Panel(
                    scan_info,
                    border_style="cyan",
                    box=box.ROUNDED
                )
            )
        
        if raw:
            # Raw mode - just show sqlmap output directly
            self.console.print("[cyan]Running sqlmap...[/cyan]\n")
            success, output = self.run_sqlmap_test(url, level, risk, data=data, verbose=verbose)
            self.console.print(output)
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task("[cyan]Scanning for vulnerabilities...", total=None)
            success, output = self.run_sqlmap_test(url, level, risk, data=data, verbose=verbose)
            progress.update(task, completed=True)
        
        parsed = self.parse_results(output)
        self.results['vulnerabilities'] = parsed['vulnerabilities']
        self.results['total_tests'] = 1
        self.results['end_time'] = datetime.now()
        
        self.display_summary()
    
    def display_summary(self):
        """Display a comprehensive summary of results"""
        self.console.print()
        
        # Calculate duration
        duration = (self.results['end_time'] - self.results['start_time']).total_seconds()
        
        # Create summary panel
        summary_text = f"""
[cyan]Target:[/cyan] {self.results['target']}
[cyan]Total Tests:[/cyan] {self.results['total_tests']}
[cyan]Duration:[/cyan] {duration:.2f} seconds
[cyan]Vulnerabilities Found:[/cyan] {len(self.results['vulnerabilities'])}
        """
        
        self.console.print(
            Panel(
                summary_text.strip(),
                title="[bold]Scan Summary[/bold]",
                border_style="green" if len(self.results['vulnerabilities']) == 0 else "red",
                box=box.DOUBLE
            )
        )
        
        # Display vulnerabilities if found
        if self.results['vulnerabilities']:
            self.console.print()
            vuln_table = Table(title="⚠️  Vulnerabilities Detected", box=box.HEAVY)
            vuln_table.add_column("Parameter", style="cyan")
            vuln_table.add_column("Type", style="yellow")
            vuln_table.add_column("Title", style="red")
            
            for vuln in self.results['vulnerabilities']:
                vuln_table.add_row(
                    vuln.get('parameter', 'N/A'),
                    vuln.get('type', 'N/A'),
                    vuln.get('title', 'N/A')
                )
            
            self.console.print(vuln_table)
            self.console.print()
            self.console.print(
                "[bold red]⚠️  SQL injection vulnerabilities detected! Take immediate action.[/bold red]"
            )
        else:
            self.console.print()
            self.console.print(
                "[bold green]✓ No SQL injection vulnerabilities detected.[/bold green]"
            )
        
        self.console.print()
    
    def interactive_mode(self):
        """Interactive mode for user input"""
        self.console.print()
        self.console.print(
            Panel(
                "[cyan]Interactive Mode[/cyan]\n[dim]Enter target details for SQL injection testing[/dim]",
                border_style="cyan"
            )
        )
        
        url = Prompt.ask("\n[cyan]Enter target URL[/cyan]")
        
        scan_type = Prompt.ask(
            "[cyan]Select scan type[/cyan]",
            choices=["quick", "comprehensive"],
            default="quick"
        )
        
        if scan_type == "quick":
            level = int(Prompt.ask("[cyan]Test level (1-5)[/cyan]", default="1"))
            risk = int(Prompt.ask("[cyan]Test risk (1-3)[/cyan]", default="1"))
            self.quick_scan(url, level, risk)
        else:
            max_level = int(Prompt.ask("[cyan]Maximum test level (1-5)[/cyan]", default="5"))
            max_risk = int(Prompt.ask("[cyan]Maximum test risk (1-3)[/cyan]", default="3"))
            self.comprehensive_scan(url, max_level, max_risk)


def main():
    parser = argparse.ArgumentParser(
        description="SQLMap CLI - Beautiful automated SQL injection testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan with default settings (GET parameter)
  python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test"
  
  # Test with POST data (JSON)
  python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/user/login" --data='{"email":"test@example.com","password":"pass123"}'
  
  # Comprehensive scan (all risk and level combinations)
  python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test" --comprehensive
  
  # Custom level and risk with POST data
  python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/user/login" --data='{"email":"test@example.com","password":"pass123"}' --level 3 --risk 2
  
  # Interactive mode
  python sqlmapcli.py --interactive
        """
    )
    
    parser.add_argument(
        '-u', '--url',
        help='Target URL (e.g., "http://example.com/page?id=1")'
    )
    
    parser.add_argument(
        '--comprehensive',
        action='store_true',
        help='Run comprehensive scan with all risk/level combinations'
    )
    
    parser.add_argument(
        '--level',
        type=int,
        default=1,
        choices=[1, 2, 3, 4, 5],
        help='Level of tests to perform (1-5, default: 1)'
    )
    
    parser.add_argument(
        '--risk',
        type=int,
        default=1,
        choices=[1, 2, 3],
        help='Risk of tests to perform (1-3, default: 1)'
    )
    
    parser.add_argument(
        '--max-level',
        type=int,
        default=5,
        choices=[1, 2, 3, 4, 5],
        help='Maximum level for comprehensive scan (default: 5)'
    )
    
    parser.add_argument(
        '--max-risk',
        type=int,
        default=3,
        choices=[1, 2, 3],
        help='Maximum risk for comprehensive scan (default: 3)'
    )
    
    parser.add_argument(
        '--technique',
        type=str,
        default='BEUSTQ',
        help='SQL injection techniques to use (default: BEUSTQ)'
    )
    
    parser.add_argument(
        '--data',
        type=str,
        help='Data string to be sent through POST (e.g., "username=test&password=test")'
    )
    
    parser.add_argument(
        '--raw',
        action='store_true',
        help='Show raw sqlmap output without formatting'
    )
    
    parser.add_argument(
        '--verbose',
        type=int,
        choices=[0, 1, 2, 3, 4, 5, 6],
        help='Sqlmap verbosity level (0-6, default: 1)'
    )
    
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Run in interactive mode'
    )
    
    args = parser.parse_args()
    
    cli = SQLMapCLI()
    cli.print_banner()
    
    # Check if sqlmap exists
    if not SQLMAP_PATH.exists():
        console.print(
            f"[bold red]Error: sqlmap.py not found at {SQLMAP_PATH}[/bold red]",
            style="bold red"
        )
        console.print("[yellow]Make sure you're running this script from the sqlmap directory[/yellow]")
        sys.exit(1)
    
    # Interactive mode
    if args.interactive:
        cli.interactive_mode()
        return
    
    # Check if URL is provided
    if not args.url:
        console.print("[bold red]Error: URL is required (use -u or --interactive)[/bold red]")
        parser.print_help()
        sys.exit(1)
    
    # Run appropriate scan
    verbose_level = args.verbose if args.verbose is not None else 1
    
    if args.comprehensive:
        cli.comprehensive_scan(
            args.url, 
            max_level=args.max_level,
            max_risk=args.max_risk,
            techniques=args.technique,
            data=args.data,
            verbose=verbose_level
        )
    else:
        cli.quick_scan(
            args.url, 
            level=args.level, 
            risk=args.risk, 
            data=args.data,
            raw=args.raw,
            verbose=verbose_level
        )


if __name__ == "__main__":
    main()
