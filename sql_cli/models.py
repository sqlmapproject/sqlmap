from typing import List, Dict, Optional, TypedDict
from datetime import datetime

SQL_TECHNIQUES = {
    "B": "Boolean-based blind",
    "E": "Error-based",
    "U": "Union query-based",
    "S": "Stacked queries",
    "T": "Time-based blind",
    "Q": "Inline queries",
}

class ScanResult(TypedDict):
    total_tests: int
    vulnerabilities: List[Dict[str, str]]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    target: Optional[str]
