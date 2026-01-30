import re
import hashlib
import random
from pathlib import Path
from datetime import datetime
from rich.console import Console

console = Console()

SQLMAP_PATH = Path(__file__).parent.parent / "sqlmap.py"
LOGS_DIR = Path(__file__).parent.parent / "logs"

def get_log_filename(url: str) -> Path:
    """Generate a log filename based on URL and timestamp with hash for uniqueness"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Create a hash of the URL to ensure uniqueness
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    # Add random component for additional uniqueness in batch scenarios
    random_component = random.randint(1000, 9999)
    # Sanitize URL for filename (keep it readable but short)
    safe_url = re.sub(r'[^\w\-_\.]', '_', url)[:30]
    return LOGS_DIR / f"sqlmap_{safe_url}_{url_hash}_{timestamp}_{random_component}.log"

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
