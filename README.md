# Web Security Scanner

This is a Python-based security auditing tool that analyzes websites for common security misconfigurations and prints a detailed report of what security measures the website has and what it's lacking.


## Features
- **Security Header Analysis**: Checks for essential HTTP security headers
  - X-Frame-Options (clickjacking protection)
  - X-Content-Type-Options (MIME-sniffing prevention)
  - Strict-Transport-Security (HTTPS enforcement)
  - Content-Security-Policy (resource loading controls)

- **SSL/TLS Certificate Validation**: Verifies websites' certificate validity and expiration dates

- **Multi-Site Scanning**: Scans multiple websites in a single run of the tool

- **JSON Export**: Saves a detailed report of the tool's findings to a structured JSON file

- **Security Scoring**: Automatically scores websites based on the security headers


## Usage

### Scanning One Site
```python
from scanner import check_url

# scan a single website
check_url('https://youtube.com')
```

### Scanning Multiple Sites
```python
from scanner import check_multiple_url

sites = [
    'https://youtube.com',
    'https://github.com',
    'https://linkedin.com'
]

# scan all websites in sites
check_multiple_url(sites)
```

The results are automatically saved to `security_scan_results.json`.

## Example Output
```
============================================================
Scanning 1/4: https://github.com
============================================================
X-Frame-Options is present in https://github.com
 -> Prevents clickjacking attacks
X-Content-Type-Options is present in https://github.com
 -> Prevents MIME-sniffing
Strict-Transport-Security is present in https://github.com
 -> Enforces HTTPS connections
Content-Security-Policy is present in https://github.com
 -> Controls what resources can load
Referrer-Policy is present in https://github.com
 -> Controls how much referrer information is shared
Permissions-Policy is missing in https://github.com
 -> Controls browser features (camera, microphone, etc.)
X-XSS-Protection is present in https://github.com
 -> Legacy XSS filter (deprecated but still checked)
Cross-Origin-Opener-Policy is missing in https://github.com
 -> Isolates browsing context from other windows
Cross-Origin-Embedder-Policy is missing in https://github.com
 -> Prevents loading unauthorized cross-origin resources
Cross-Origin-Resource-Policy is missing in https://github.com
 -> Protects resources from being loaded by other origins
The security score for this website is 6/10 (60.0%)

SSL Certificate Info:
  -> Issued to: github.com
  -> Expires: 2026-02-05
  -> Days until expiry: 40
```

## Potential Improvements
- Command-line interface
- HTML report generation for better visualization
- Additional security checks
- Database storage for long-term tracking

## Author
**Adam Kim** - Cybersecurity & Business Administration Major @ Northeastern University




