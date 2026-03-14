# SQLMap CLI - Examples

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Basic Usage

### 1. Quick Scan (Default: Level 1, Risk 1)
Test a single URL with minimal risk:

```bash
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test"
```

### 2. Comprehensive Scan
Test all combinations of risk (1-3) and levels (1-5) automatically:

```bash
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test" --comprehensive
```

This runs **15 tests total** (5 levels × 3 risks) and provides a complete vulnerability assessment.

### 3. Custom Level and Risk
Run a specific test configuration:

```bash
# Medium level, medium risk
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test" --level 3 --risk 2

# High level, high risk
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test" --level 5 --risk 3
```

### 4. Interactive Mode
Get guided prompts for easy testing:

```bash
python sqlmapcli.py --interactive
```

This will ask you:
- Target URL
- Whether the request requires POST data/body
- POST data/body (if needed) - supports JSON or form data
- Scan type (quick or comprehensive)
- Custom level and risk settings

### 5. Custom Comprehensive Scan
Limit the comprehensive scan to specific max values:

```bash
# Test only up to level 3 and risk 2
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test" --comprehensive --max-level 3 --max-risk 2
```

### 6. Raw Output Mode
Get the exact same output as running sqlmap directly:

```bash
# Show raw sqlmap output without formatting
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/user/login" --data='{"email":"test@example.com","password":"pass123"}' --level 2 --risk 2 --raw

# Increase verbosity for more details
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/user/login" --data='{"email":"test@example.com","password":"pass123"}' --verbose 3 --raw
```

**Note**: The `--raw` flag ensures the CLI output matches sqlmap exactly, bypassing all formatting and parsing.

### 7. Batch Mode - Test Multiple Endpoints
Test multiple endpoints with concurrency:

```bash
# Test multiple endpoints from a JSON file with auto-scaled concurrency (default, typically 2x CPU cores)
python sqlmapcli.py -b endpoints.json --level 2 --risk 2

# Test with specific concurrency (10 concurrent scans)
python sqlmapcli.py -b endpoints.json --level 2 --risk 2 --concurrency 10

# Test with custom settings
python sqlmapcli.py -b endpoints.json --level 3 --risk 2 --concurrency 5
```

**Batch File Format** (`endpoints.json`):
```json
[
  {
    "url": "https://demo.owasp-juice.shop/rest/products/search?q=test"
  },
  {
    "url": "https://demo.owasp-juice.shop/rest/user/login",
    "data": "{\"email\":\"test@example.com\",\"password\":\"password123\"}"
  },
  {
    "url": "https://demo.owasp-juice.shop/api/Users/1"
  }
]
```

**Features**:
- Tests N endpoints with M concurrency
- Automatically saves logs for each endpoint
- Displays progress and summary table
- Supports both GET and POST requests

### 8. Log Management

Logs are automatically saved to the `logs/` folder:

```bash
# Run scan with logging (default behavior)
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test"
# Log saved to: logs/sqlmap_https___demo_owasp_juice_shop_rest_produ_20260107_123456.log

# Disable logging if needed
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test" --no-logs
```

**Log Features**:
- Automatic log folder creation
- Timestamped log files
- Sanitized filenames based on URL
- Complete sqlmap output saved

## Real-World Testing Example

**Using OWASP Juice Shop Demo** (a legitimate vulnerable application for security testing):

```bash
# Quick scan on OWASP Juice Shop REST API with GET parameter
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/products/search?q=test" --level 2 --risk 2

# Test login endpoint with POST data (JSON)
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/user/login" --data='{"email":"test@example.com","password":"password123"}' --level 2 --risk 2

# Comprehensive scan on login endpoint
python sqlmapcli.py -u "https://demo.owasp-juice.shop/rest/user/login" --data='{"email":"test@example.com","password":"password123"}' --comprehensive
```

This is a real, legitimate target designed for security testing and learning.

## Understanding Levels and Risks

### Levels (1-5)
- **Level 1**: Default, tests GET and POST parameters
- **Level 2**: Adds HTTP Cookie header testing
- **Level 3**: Adds HTTP User-Agent/Referer headers testing
- **Level 4**: Deeper tests with more payloads
- **Level 5**: Maximum depth, most comprehensive

### Risks (1-3)
- **Risk 1**: Safe for all databases, minimal intrusion
- **Risk 2**: May include time-based tests (slight delay)
- **Risk 3**: Aggressive tests (may cause OR attacks on UPDATE/INSERT)

## Output Examples

### Successful Scan (No Vulnerabilities)
```
╔════════════════════════════════════════════════════ Scan Summary ════════════════════════════════════════════════════╗
║ Target: http://example.com/page?id=1                                                                                 ║
║ Total Tests: 1                                                                                                       ║
║ Duration: 12.45 seconds                                                                                              ║
║ Vulnerabilities Found: 0                                                                                             ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

✓ No SQL injection vulnerabilities detected.
```

### Vulnerable Target Found
```
                              ⚠️  Vulnerabilities Detected                               
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Parameter ┃ Type                ┃ Title                                              ┃
┣━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ id        ┃ boolean-based blind ┃ AND boolean-based blind - WHERE or HAVING clause   ┃
┃ id        ┃ time-based blind    ┃ MySQL >= 5.0.12 AND time-based blind (query SLEEP) ┃
┗━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

⚠️  SQL injection vulnerabilities detected! Take immediate action.
```

## Features Showcase

✨ **Beautiful UI with Rich**
- Colored output for easy reading
- Progress bars showing scan status
- Tables for organized results
- Panels for important information

⚡ **One-Line Testing**
- Run all risk/level combinations with `--comprehensive`
- No need to manually iterate through tests
- Automatic result aggregation

📊 **Clear Summaries**
- See exactly what was tested
- Color-coded findings (red = vulnerable, green = safe)
- Detailed vulnerability tables
- Duration tracking

🎯 **User-Friendly**
- Interactive mode for beginners
- Flexible command-line options for experts
- Clear help messages

## Tips

1. **Start with quick scan**: Always start with a quick scan to see if the target is vulnerable
2. **Use comprehensive for thorough testing**: If vulnerabilities are found, use comprehensive mode
3. **Adjust timeout if needed**: Some tests may take longer on slow networks
4. **Legal use only**: Only test targets you have explicit permission to test

## Testing Resources

**⚠️ IMPORTANT**: Only test websites you own or have explicit written permission to test.

For learning and practice, you can use legitimate SQL injection testing websites designed for security education:

- **DVWA** (Damn Vulnerable Web Application) - Set up locally
- **WebGoat** - OWASP's deliberately insecure application
- **bWAPP** - Buggy Web Application for practicing
- **OWASP Juice Shop** - Modern vulnerable web application
- **Local test environments** - Set up your own vulnerable applications

Always ensure you have permission before testing any website. Unauthorized testing is illegal.
