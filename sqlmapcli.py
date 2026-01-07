#!/usr/bin/env python3
"""
SQLMap CLI - A beautiful CLI wrapper for sqlmap
Automates comprehensive SQL injection testing with a single command
"""

import sys
import argparse
import json
from pathlib import Path

# Add the current directory to path so we can import from sql_cli
sys.path.append(str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
except ImportError:
    print("Error: 'rich' library is required. Install it with: pip install rich")
    sys.exit(1)

from sql_cli.scanner import SQLMapScanner
from sql_cli.utils import SQLMAP_PATH
from sql_cli.ui import print_banner

console = Console()


def interactive_mode(scanner: SQLMapScanner):
    """Interactive mode for user input"""
    console.print()
    console.print(
        Panel(
            "[cyan]Interactive Mode[/cyan]\n[dim]Enter target details for SQL injection testing[/dim]",
            border_style="cyan",
        )
    )

    url = Prompt.ask("\n[cyan]Enter target URL[/cyan]")

    # Ask if this is a POST request
    has_data = Confirm.ask(
        "[cyan]Does this request require POST data/body?[/cyan]", default=False
    )

    data = None
    if has_data:
        console.print("\n[dim]Examples:[/dim]")
        console.print(
            '[dim]  JSON: {"email":"test@example.com","password":"pass123"}[/dim]'
        )
        console.print("[dim]  Form: username=admin&password=secret[/dim]")
        data = Prompt.ask("\n[cyan]Enter POST data/body[/cyan]")

    # Ask for custom headers
    has_headers = Confirm.ask(
        "[cyan]Do you need to add custom headers (Auth, etc.)?[/cyan]", default=False
    )

    headers = None
    if has_headers:
        console.print("\n[dim]Example:[/dim]")
        console.print(
            '[dim]  "Authorization: Bearer token; Cookie: PHPSESSID=..."[/dim]'
        )
        headers = Prompt.ask("\n[cyan]Enter headers[/cyan]")

    scan_type = Prompt.ask(
        "\n[cyan]Select scan type[/cyan]",
        choices=["quick", "comprehensive"],
        default="quick",
    )

    if scan_type == "quick":
        # Input validation for level and risk
        while True:
            try:
                level_str = Prompt.ask("[cyan]Test level (1-5)[/cyan]", default="1")
                level = int(level_str)
                if 1 <= level <= 5:
                    break
                console.print("[red]Level must be between 1 and 5[/red]")
            except ValueError:
                console.print("[red]Please enter a valid number[/red]")
        
        while True:
            try:
                risk_str = Prompt.ask("[cyan]Test risk (1-3)[/cyan]", default="1")
                risk = int(risk_str)
                if 1 <= risk <= 3:
                    break
                console.print("[red]Risk must be between 1 and 3[/red]")
            except ValueError:
                console.print("[red]Please enter a valid number[/red]")
        
        scanner.quick_scan(url, level, risk, data=data, headers=headers)
    else:
        # Input validation for max_level and max_risk
        while True:
            try:
                max_level_str = Prompt.ask("[cyan]Maximum test level (1-5)[/cyan]", default="5")
                max_level = int(max_level_str)
                if 1 <= max_level <= 5:
                    break
                console.print("[red]Level must be between 1 and 5[/red]")
            except ValueError:
                console.print("[red]Please enter a valid number[/red]")
        
        while True:
            try:
                max_risk_str = Prompt.ask("[cyan]Maximum test risk (1-3)[/cyan]", default="3")
                max_risk = int(max_risk_str)
                if 1 <= max_risk <= 3:
                    break
                console.print("[red]Risk must be between 1 and 3[/red]")
            except ValueError:
                console.print("[red]Please enter a valid number[/red]")
        
        scanner.comprehensive_scan(url, max_level, max_risk, data=data, headers=headers)


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
  
  # Batch mode - test multiple endpoints from JSON file
  python sqlmapcli.py -b endpoints.json --level 2 --risk 2
  
  # Interactive mode
  python sqlmapcli.py --interactive
""",
    )

    parser.add_argument(
        "-u", "--url", help='Target URL (e.g., "http://example.com/page?id=1")'
    )
    parser.add_argument(
        "--comprehensive", action="store_true", help="Run comprehensive scan"
    )
    parser.add_argument(
        "--level",
        type=int,
        default=1,
        choices=[1, 2, 3, 4, 5],
        help="Level (1-5, default: 1)",
    )
    parser.add_argument(
        "--risk", type=int, default=1, choices=[1, 2, 3], help="Risk (1-3, default: 1)"
    )
    parser.add_argument(
        "--max-level",
        type=int,
        default=5,
        choices=[1, 2, 3, 4, 5],
        help="Max level for comprehensive",
    )
    parser.add_argument(
        "--max-risk",
        type=int,
        default=3,
        choices=[1, 2, 3],
        help="Max risk for comprehensive",
    )
    parser.add_argument(
        "--technique",
        type=str,
        default="BEUSTQ",
        help="SQL techniques (default: BEUSTQ)",
    )
    parser.add_argument("--data", type=str, help="POST data")
    parser.add_argument("--headers", type=str, help="Extra headers")
    parser.add_argument("--raw", action="store_true", help="Show raw sqlmap output")
    parser.add_argument(
        "--verbose", type=int, choices=[0, 1, 2, 3, 4, 5, 6], help="Verbosity (0-6)"
    )
    parser.add_argument(
        "-i", "--interactive", action="store_true", help="Interactive mode"
    )
    parser.add_argument("-b", "--batch-file", type=str, help="Path to batch JSON")
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=0,
        help="Number of concurrent scans (default: 0 for auto-scale)",
    )
    parser.add_argument("--no-logs", action="store_true", help="Disable logs")

    args = parser.parse_args()

    scanner = SQLMapScanner(enable_logging=not args.no_logs)
    print_banner()

    if not SQLMAP_PATH.exists():
        console.print(
            f"[bold red]Error: sqlmap.py not found at {SQLMAP_PATH}[/bold red]"
        )
        sys.exit(1)

    if args.interactive:
        interactive_mode(scanner)
        return

    if args.batch_file:
        try:
            with open(args.batch_file, "r") as f:
                endpoints = json.load(f)

            if not isinstance(endpoints, list):
                console.print(
                    "[bold red]Error: Batch file must contain a JSON array[/bold red]"
                )
                sys.exit(1)

            verbose_level = args.verbose if args.verbose is not None else 1
            scanner.batch_scan(
                endpoints,
                level=args.level,
                risk=args.risk,
                concurrency=args.concurrency,
                verbose=verbose_level,
            )
            return
        except FileNotFoundError:
            console.print(
                f"[bold red]Error: Batch file not found: {args.batch_file}[/bold red]"
            )
            sys.exit(1)
        except json.JSONDecodeError as e:
            console.print(
                f"[bold red]Error: Invalid JSON in batch file '{args.batch_file}': {e}[/bold red]"
            )
            sys.exit(1)
        except PermissionError:
            console.print(
                f"[bold red]Error: Permission denied when reading batch file: {args.batch_file}[/bold red]"
            )
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error loading batch file: {e}[/bold red]")
            sys.exit(1)

    if not args.url:
        console.print("[bold red]Error: URL is required[/bold red]")
        parser.print_help()
        sys.exit(1)

    verbose_level = args.verbose if args.verbose is not None else 1

    if args.comprehensive:
        scanner.comprehensive_scan(
            args.url,
            max_level=args.max_level,
            max_risk=args.max_risk,
            techniques=args.technique,
            data=args.data,
            headers=args.headers,
            verbose=verbose_level,
        )
    else:
        scanner.quick_scan(
            args.url,
            level=args.level,
            risk=args.risk,
            data=args.data,
            headers=args.headers,
            raw=args.raw,
            verbose=verbose_level,
        )


if __name__ == "__main__":
    main()
