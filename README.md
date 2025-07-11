# CDN SNI Scanner PLUS

A simple and powerful Python tool to scan and identify valid **CDN IP + SNI (Server Name Indication)** pairs for Cloudflare, Fastly, Gcore.

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- Multi-CDN support: Cloudflare, Fastly, Gcore
- Supports both IPv4 & IPv6
- Batch scan domains from a file
- Random IP scan from CDN ranges
- JSON & TXT output
- Configurable rate limiting
- Debug & verbose modes

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
    ```bash
    pip install -r requirements.txt
    #manualy
    pip install colorama dnspython urllib3 requests openpyxl
    ```
   

---

## Usage

Run the scanner:
```bash
python cdn_scanner_plus.py
```
for updateing ip lists its better to use vpn but for rest of the way vpn off is smart choice
**Menu Options:**

| Option | Description                      |
|--------|----------------------------------|
|   1    | Scan single domain               |
|   2    | Scan random IPs from CDN ranges  |
|   3    | Scan domains from file           |
|   4    | View saved results               |
|   5    | Toggle debug mode                |
|   6    | Test known CDNs                  |
|   7    | Deep test specific CDN           |
|   8    | Edit configuration               |
|   9    | Exit                             |

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

MIT License — Free for personal and commercial use.

---

⭐ **Star this repo if you find it useful!** ⭐
