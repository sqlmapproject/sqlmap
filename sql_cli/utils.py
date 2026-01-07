import re
from pathlib import Path
from datetime import datetime
from rich.console import Console

console = Console()

SQLMAP_PATH = Path(__file__).parent.parent / "sqlmap.py"
LOGS_DIR = Path(__file__).parent.parent / "logs"

def get_log_filename(url: str) -> Path:
    """Generate a log filename based on URL and timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize URL for filename
    safe_url = re.sub(r'[^\w\-_\.]', '_', url)[:50]
    return LOGS_DIR / f"sqlmap_{safe_url}_{timestamp}.log"

def save_log(log_file: Path, content: str):
    """Save content to log file"""
    try:
        if not LOGS_DIR.exists():
            LOGS_DIR.mkdir(exist_ok=True)
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(content)
        console.print(f"[dim]Log saved to: {log_file}[/dim]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save log: {e}[/yellow]")
