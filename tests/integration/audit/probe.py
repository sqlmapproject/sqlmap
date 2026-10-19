#!/usr/bin/env python
"""Execute fixture SQL over a real DB-API connection for ground-truth checks."""
import json
import sys
from db import connect
conn = connect(sys.argv[1])
try:
    cursor = conn.cursor()
    cursor.execute(sys.stdin.read())
    print(json.dumps(cursor.fetchall() if cursor.description else [], default=str))
finally:
    conn.close()
