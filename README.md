# SecureScan


`SecureScan` is a command-line interface (CLI) tool written in Go, designed to perform security analysis on websites. It evaluates SSL certificates, performs a deep-level analysis of HTTP security headers, and detects common phishing patterns.

This tool helps identify vulnerabilities related to SSL stripping, clickjacking, Cross-Site Scripting (XSS), MIME-type sniffing, insecure cookie implementations, and more.

## Features
* **SSL Certificate Check**: Verifies the validity of a website's SSL/TLS certificate.
* **Advanced HTTP Header Analysis**: Scans for critical security headers (HSTS, CSP, X-Frame-Options, etc.). It flags missing headers, insecure configurations (like improper CORS or outdated server versions), and insecure cookies (missing `HttpOnly` or `Secure` flags).
* **Phishing Pattern Detection**: Scans URLs for common keywords and patterns associated with phishing websites.
* **File-Based Reporting**: Saves a detailed, time-stamped report of all findings to a specified file.
* **Batch Scanning**: Supports scanning multiple URLs from a text file.
* **System Information**: Displays host system info (OS, IPs) on startup.

## Installation

1.  Ensure you have [Go](https://golang.org/doc/install) (1.16 or later) installed.

2.  Clone this repository:
    ```bash
    git clone [https://github.com/](https://github.com/)mansis30/SecureScan.git
    ```


3.  Navigate to the project directory:
    ```bash
    cd SecureScan
    ```

4.  Build the executable:
    ```bash
    go build -o secure-scan
    ```
    This will create a binary file named `secure-scan` in the directory.

## Usage

You can run the tool in two main ways:

### Interactive Mode

Simply run the built executable to scan a single URL. The tool will save the results to `results.txt` by default.

```bash
./secure-scan

# Scan a single URL (the tool will prompt you)
./secure-scan -report "my_report.txt"


# Run a batch scan using urls.txt
./secure-scan -batch urls.txt

# Run a batch scan with verbose output and a custom report file
./secure-scan -v -batch urls.txt -report "batch_report.txt"

$ ./secure-scan
===============================
            SecureScan
        made by Mansi Singh
===============================

System Information:
System: darwin (amd64)
Hostname: Mansi-MacBook
Local IP Address: 192.168.1.10
External IP Address: 203.0.113.5

Enter the URL to check: insecure-website.com
Scan complete. Results saved to results.txt
