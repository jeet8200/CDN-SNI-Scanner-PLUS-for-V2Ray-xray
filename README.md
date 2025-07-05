# CDN SNI Scanner PLUS

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A powerful Python tool to scan and identify valid **CDN IP + SNI (Server Name Indication)** pairs for Cloudflare, Fastly, Gcore, Akamai, and CloudFront.

## Features

- ✅ Multi-CDN support (Cloudflare, Fastly, Gcore, Akamai, CloudFront)
- ✅ IPv4/IPv6 compatibility
- ✅ Batch scanning from files
- ✅ Random IP scanning from CDN ranges
- ✅ JSON and TXT output
- ✅ Configurable rate limiting
- ✅ Debug and verbose modes

## Installation

### 1. Install Python 3.7+

- **Windows**: Download from [python.org](https://www.python.org/downloads/)
  - Check "Add Python to PATH" during installation
- **Linux/macOS**:
  ```bash
  # Debian/Ubuntu
  sudo apt update && sudo apt install python3 python3-pip
  
  # macOS (Homebrew)
  brew install python

2. Clone the Repository
bash

git clone https://github.com/jeet8200/CDN-SNI-Scanner-PLUS-for-V2Ray-xray/
cd cdn-sni-scanner-plus

3. Install Dependencies
bash

pip install -r requirements.txt

Usage

Run the scanner:
bash

python cdn_scanner_plus.py

Menu Options

Option	Description

1	Scan single domain

2	Scan random IPs from CDN ranges

3	Scan domains from file

4	View saved results

5	Toggle debug mode

6	Test known CDNs

7	Deep test specific CDN

8	Edit configuration

9	Exit

Examples

    Scan a single domain:
    text

> python cdn_scanner_plus.py
> Select option 1
> Enter domain: example.com

Batch scan from file:
Create domains.txt with one domain per line, then select option 3.

Test Cloudflare IPs:
text

    > Select option 2
    > Choose Cloudflare
    > Enter 100 IPs to test
    > Enter SNI: example.com

Configuration

Edit config.ini to:

    Change DNS servers

    Adjust rate limits

    Add custom CDN IP ranges

Output

Results are saved in:

    results/valid_pairs.json (structured data)

    results/valid_pairs.txt (readable format)

Troubleshooting

    "Python not found": Ensure Python is in PATH or use python3

    SSL errors: Expected - tool ignores verification for compatibility

    Slow scans: Decrease rate_limit_delay in config

License

MIT License - Free for personal and commercial use.

⭐ Star this repo if you find it useful! ⭐
text




### Or Download Directly:
```bash
curl -o README.md https://raw.githubusercontent.com/yourusername/cdn-sni-scanner-plus/main/README.md
