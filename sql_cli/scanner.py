from rich.table import Table
import sys
import subprocess
import json
import os
import tempfile
import shutil
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.panel import Panel
from rich import box

from .models import ScanResult
from .utils import SQLMAP_PATH, get_log_filename, save_log
from .ui import display_summary, display_batch_results

console = Console()


class SQLMapScanner:
    def __init__(self, enable_logging: bool = True):
        self.enable_logging = enable_logging
        self.results: ScanResult = {
            "total_tests": 0,
            "vulnerabilities": [],
            "start_time": None,
            "end_time": None,
            "target": None,
        }

    def run_sqlmap_test(
        self,
        url: str,
        level: int,
        risk: int,
        technique: str = "BEUSTQ",
        batch: bool = True,
        data: Optional[str] = None,
        headers: Optional[str] = None,
        verbose: int = 1,
        extra_args: Optional[List[str]] = None,
        progress: Optional[Progress] = None,
        task_id: Any = None,
    ) -> Tuple[bool, str]:
        """Run sqlmap with specified parameters and optional real-time progress"""
        cmd = [
            sys.executable,
            str(SQLMAP_PATH),
            "-u",
            url,
            f"--level={level}",
            f"--risk={risk}",
            f"--technique={technique}",
            "-v",
            str(verbose),
        ]

        if batch:
            cmd.append("--batch")

        if data:
            cmd.extend(["--data", data, "--method", "POST"])

        if headers:
            cmd.extend(["--headers", headers])

        if extra_args:
            cmd.extend(extra_args)

        # Create a unique temporary directory for this run to avoid session database locks
        # which are the primary cause of concurrency bottlenecks in sqlmap
        tmp_output_dir = tempfile.mkdtemp(prefix="sqlmap_scan_")
        cmd.extend(["--output-dir", tmp_output_dir])

        try:
            if progress and task_id:
                # Run with real-time output parsing
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                output_lines = []
                if process.stdout is None:
                    return False, "Failed to capture sqlmap output"
                for line in process.stdout:
                    output_lines.append(line)

                    # Update progress description based on sqlmap status
                    clean_line = line.strip()
                    if "[INFO]" in clean_line:
                        status = clean_line.split("[INFO]", 1)[1].strip()
                        # Clean up status message
                        if "testing" in status.lower():
                            progress.update(
                                task_id, description=f"[cyan]{status[:50]}[/cyan]"
                            )
                        elif "detecting" in status.lower():
                            progress.update(
                                task_id, description=f"[yellow]{status[:50]}[/yellow]"
                            )
                        elif "identified" in status.lower():
                            progress.update(
                                task_id, description=f"[green]{status[:50]}[/green]"
                            )

                process.wait()
                full_output = "".join(output_lines)

                # Cleanup temporary output directory
                try:
                    shutil.rmtree(tmp_output_dir)
                except:
                    pass

                return process.returncode == 0, full_output
            else:
                # Standard blocking run
                result = subprocess.run(cmd, capture_output=True, text=True)

                # Cleanup temporary output directory
                try:
                    shutil.rmtree(tmp_output_dir)
                except:
                    pass

                return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            # Cleanup on error
            try:
                shutil.rmtree(tmp_output_dir)
            except:
                pass
            return False, str(e)

    def parse_results(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output for vulnerabilities"""
        vulns = []

        # Look for vulnerability indicators
        if "sqlmap identified the following injection point" in output:
            lines = output.split("\n")
            current_param = "Unknown"

            for i, line in enumerate(lines):
                if "Parameter:" in line:
                    current_param = line.split("Parameter:")[1].strip()
                elif "Type:" in line:
                    vuln_type = line.split("Type:")[1].strip()
                    if i + 1 < len(lines) and "Title:" in lines[i + 1]:
                        title = lines[i + 1].split("Title:")[1].strip()
                        vulns.append(
                            {
                                "parameter": current_param,
                                "type": vuln_type,
                                "title": title,
                            }
                        )

        backend_dbms = None
        if "back-end DBMS:" in output.lower():
            for line in output.split("\n"):
                if "back-end DBMS:" in line.lower():
                    backend_dbms = line.split(":", 1)[1].strip()
                    break

        return {
            "vulnerabilities": vulns,
            "backend_dbms": backend_dbms,
            "is_vulnerable": len(vulns) > 0 or "vulnerable" in output.lower(),
        }

    def comprehensive_scan(
        self,
        url: str,
        max_level: int = 5,
        max_risk: int = 3,
        techniques: str = "BEUSTQ",
        data: Optional[str] = None,
        headers: Optional[str] = None,
        verbose: int = 1,
    ):
        """Run comprehensive scan with all levels and risks"""
        self.results["target"] = url
        self.results["start_time"] = datetime.now()

        results_table = Table(title="Scan Results", box=box.ROUNDED)
        results_table.add_column("Level", style="cyan", justify="center")
        results_table.add_column("Risk", style="yellow", justify="center")
        results_table.add_column("Status", justify="center")
        results_table.add_column("Findings", style="magenta")

        total_tests = max_level * max_risk

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            overall_task = progress.add_task(
                f"[cyan]Scanning {url}...", total=total_tests
            )

            for level in range(1, max_level + 1):
                for risk in range(1, max_risk + 1):
                    progress.update(
                        overall_task,
                        description=f"[cyan]Testing Level {level}, Risk {risk}...[/cyan]",
                    )

                    success, output = self.run_sqlmap_test(
                        url,
                        level,
                        risk,
                        techniques,
                        data=data,
                        headers=headers,
                        verbose=max(verbose, 3),
                        progress=progress,
                        task_id=overall_task,
                    )
                    parsed = self.parse_results(output)

                    status = "✓" if success else "✗"
                    status_style = "green" if success else "red"

                    findings = (
                        "No vulnerabilities"
                        if not parsed["is_vulnerable"]
                        else f"{len(parsed['vulnerabilities'])} found!"
                    )
                    findings_style = (
                        "green" if not parsed["is_vulnerable"] else "bold red"
                    )

                    if parsed["is_vulnerable"]:
                        self.results["vulnerabilities"].extend(
                            parsed["vulnerabilities"]
                        )

                    results_table.add_row(
                        str(level),
                        str(risk),
                        f"[{status_style}]{status}[/{status_style}]",
                        f"[{findings_style}]{findings}[/{findings_style}]",
                    )

                    progress.update(overall_task, advance=1)
                    self.results["total_tests"] += 1

        self.results["end_time"] = datetime.now()
        console.print()
        console.print(results_table)
        display_summary(self.results)

    def quick_scan(
        self,
        url: str,
        level: int = 1,
        risk: int = 1,
        data: Optional[str] = None,
        headers: Optional[str] = None,
        raw: bool = False,
        verbose: int = 1,
    ):
        """Run a quick scan with default settings"""
        self.results["target"] = url
        self.results["start_time"] = datetime.now()

        if not raw:
            scan_info = f"[cyan]Running quick scan on:[/cyan]\n[yellow]{url}[/yellow]\n[dim]Level: {level}, Risk: {risk}[/dim]"
            if data:
                scan_info += f"\n[dim]POST Data: {data}[/dim]"
            if headers:
                scan_info += f"\n[dim]Headers: {headers}[/dim]"

            console.print(Panel(scan_info, border_style="cyan", box=box.ROUNDED))

        if raw:
            console.print("[cyan]Running sqlmap...[/cyan]\n")
            success, output = self.run_sqlmap_test(
                url, level, risk, data=data, headers=headers, verbose=verbose
            )
            console.print(output)

            if self.enable_logging:
                log_file = get_log_filename(url)
                save_log(log_file, output)
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning {url[:40]}...", total=None)
            success, output = self.run_sqlmap_test(
                url,
                level,
                risk,
                data=data,
                headers=headers,
                verbose=max(verbose, 3),
                progress=progress,
                task_id=task,
            )
            progress.update(
                task, completed=True, description="[green]✓ Scan Complete[/green]"
            )

        if self.enable_logging:
            log_file = get_log_filename(url)
            save_log(log_file, output)

        parsed = self.parse_results(output)
        self.results["vulnerabilities"] = parsed["vulnerabilities"]
        self.results["total_tests"] = 1
        self.results["end_time"] = datetime.now()

        display_summary(self.results)

    def process_single_endpoint(
        self,
        endpoint: Dict,
        level: int,
        risk: int,
        verbose: int,
        progress: Optional[Progress] = None,
        task_id: Any = None,
    ) -> Dict:
        """Process a single endpoint for batch mode"""
        url = str(endpoint.get("url")) if endpoint.get("url") else ""

        data = endpoint.get("data")
        if data is not None and not isinstance(data, str):
            data = json.dumps(data)

        headers = endpoint.get("headers")
        if headers is not None and isinstance(headers, list):
            headers = "\\n".join(headers)

        try:
            # Force verbosity 3 for better progress tracking if in batch mode
            # unless a specific high verbosity is already requested
            exec_verbose = max(verbose, 3) if progress else verbose

            success, output = self.run_sqlmap_test(
                url,
                level,
                risk,
                data=data,
                headers=headers,
                verbose=exec_verbose,
                progress=progress,
                task_id=task_id,
            )

            if self.enable_logging:
                log_file = get_log_filename(url)
                save_log(log_file, output)

            parsed = self.parse_results(output)

            if progress and task_id:
                status_color = "red" if parsed["is_vulnerable"] else "green"
                status_text = "Vulnerable" if parsed["is_vulnerable"] else "Clean"
                progress.update(
                    task_id,
                    description=f"[{status_color}]✓ {status_text}[/{status_color}] - {url[:30]}...",
                    completed=100,
                )

            return {
                "url": url,
                "data": data,
                "success": success,
                "vulnerabilities": parsed["vulnerabilities"],
                "is_vulnerable": parsed["is_vulnerable"],
            }
        except Exception as e:
            if progress and task_id:
                progress.update(
                    task_id,
                    description=f"[bold red]✗ Error: {str(e)[:30]}[/bold red]",
                    completed=100,
                )
            return {
                "url": url,
                "data": data,
                "success": False,
                "error": str(e),
                "vulnerabilities": [],
                "is_vulnerable": False,
            }

    def batch_scan(
        self,
        endpoints: List[Dict],
        level: int = 1,
        risk: int = 1,
        concurrency: int = 5,
        verbose: int = 1,
    ):
        """Run batch scan on multiple endpoints with concurrency"""

        # Determine actual concurrency
        if concurrency <= 0:
            # For I/O bound tasks like scanning, we can use 2x CPU count
            concurrency = (os.cpu_count() or 2) * 2

        console.print(
            Panel(
                f"[cyan]Batch Scan Mode[/cyan]\n"
                f"[dim]Testing {len(endpoints)} endpoint(s) with concurrency={concurrency}[/dim]\n"
                f"[dim]Level: {level}, Risk: {risk}[/dim]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            expand=True,
        ) as progress:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                future_to_endpoint = {}

                for endpoint in endpoints:
                    url = endpoint.get("url", "Unknown")
                    task_id = progress.add_task(
                        f"[dim]Waiting...[/dim] {url[:40]}...", total=100
                    )
                    future = executor.submit(
                        self.process_single_endpoint,
                        endpoint,
                        level,
                        risk,
                        verbose,
                        progress,
                        task_id,
                    )
                    future_to_endpoint[future] = endpoint

                for future in as_completed(future_to_endpoint):
                    endpoint = future_to_endpoint[future]
                    try:
                        results.append(future.result())
                    except Exception as e:
                        results.append(
                            {
                                "url": endpoint.get("url"),
                                "data": endpoint.get("data"),
                                "success": False,
                                "error": str(e),
                                "vulnerabilities": [],
                                "is_vulnerable": False,
                            }
                        )

        display_batch_results(results)
        return results
