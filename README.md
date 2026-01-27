# CDN SNI Scanner PLUS

A simple Python tool to scan and identify valid **CDN IP + SNI (Server Name Indication)** pairs for Cloudflare, Fastly, Gcore.
                          
![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

Features

  -  Single Domain & Batch Scanning: Scan one domain or a list of domains for valid CDN IP/SNI pairs.
  -  Random IP Scanning: Generate and test random IPs from CDN ranges.
  -  Optimized CDN Ranges: Built-in ranges for Cloudflare, Gcore, Fastly (can be updated automatically).
  -  Multi-Protocol Checks: Tests both HTTPS and HTTP connectivity.
  -  Cloudflare Or Any CDN Multi-Port Scanner
  -  Xray/V2Ray Compatibility Tests: Verifies found pairs for Xray/V2Ray support.
  -  Performance Metrics: SSL handshake time, ping, HTTP response time.
  -  Export Results: Save to JSON, TXT, CSV, Excel, and generate HTML reports.
  -  Configurable: Edit DNS servers, output directory, debug/verbose modes, and more.
  -  Interactive CLI Menu: Easy-to-use terminal interface.
  -  Extra Xray Client Parser Editor in xrayparser.html
---

## Installation

1. **Install Python 3.7+**

   - **Windows:** Download from [python.org](https://www.python.org/downloads/)  
     (Check "Add Python to PATH" during install)
   - **Linux/macOS:**
     ```bash
     # Debian/Ubuntu
     sudo apt update && sudo apt install python3 python3-pip
     # macOS (Homebrew)
     brew install python
     ```

2. **Clone the Repository**
    ```bash
    git clone https://github.com/jeet8200/CDN-SNI-Scanner-PLUS-for-V2Ray-xray.git
    cd CDN-SNI-Scanner-PLUS-for-V2Ray-xray
    ```

3. **Install Dependencies**
  
    #manualy
   ```
   pip install colorama dnspython urllib3 requests openpyxl
    
  
## Usage

Run the scanner:
```bash
python cdn_scanner_plus.py
```
1: for updateing ip lists its better to use vpn but for rest of the way vpn off is smart choice

2 ****FOR XRAY TEST FIRST SCAN SOME IPS  THAN CHECK THAT IPS ON XRAY TEST THAN GENERATE HTML****

REST ARE self explanatory

**Menu Options:**

[1]  Scan single domain

[2] Scan random IPs

[3] Scan from file

[4] View results

[5] Toggle debug

[6] Test known CDNs

[7] Deep CDN Test

[8] Update CDN IP ranges      # 4 better search its better be up to date    with vpn 

[9] Generate HTML report

[10] Export to CSV/Excel    || in ("cdn_scanner_plus-3.py")  [10] Cloudflare Or Any CDN Multi-Port Scanner  not sure about the usecase Yet.

[11] Configuration

[12] Test Xray/V2Ray compatibility

[0] Exit
---

## Examples


**Scan a single domain:**
```text
> python cdn_scanner_plus.py
> Select option 1
> Enter domain: example.com
```

**Batch scan from file:**
- Put domains in `domains.txt` (one per line)
- Choose option 3 in the menu

**Test random Cloudflare IPs:**
```text
> Select option 2
> Choose Cloudflare
> Enter number of IPs: 100
> Enter SNI: example.com
```

---

## Configuration

- Edit `config.ini` to change DNS servers, rate limits, or add custom CDN IP ranges.

---

## Output

- Results saved in `results/valid_pairs.json` (JSON) and `results/valid_pairs.txt` (TXT)

---

## Troubleshooting

- **"Python not found"**: Make sure Python is in your PATH or use `python3`
- **SSL errors**: Normal — tool ignores SSL verification
- **Slow scans**: Lower `rate_limit_delay` in `config.ini`

---

## License

MIT License — Free for personal Use

---

⭐ **Star this repo if you find it useful!** ⭐
