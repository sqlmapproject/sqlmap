from typing import List, Dict, Optional, TypedDict
from datetime import datetime


class ScanResult(TypedDict):
    total_tests: int
    vulnerabilities: List[Dict[str, str]]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    target: Optional[str]
