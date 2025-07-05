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
