#!/usr/bin/env python3
"""
CDN SNI Scanner PLUS - Improved Version
GFW optimized for VLESS + WS / VLESS + XHTTP / Xray

Features:
- Random scan = port 443 only (HTTPS) + always checks port 80 (HTTP)
- Multi-port stays completely separate
- Optional WebSocket upgrade probe (user chooses, slower but more realistic for WS)
- Dual protocol reporting (http_works + https_works)
- Quality ranking
- VLESS snippet generator Custom(uuid path host) creating vless_snippets.txt 
- Colorful user-friendly HTML report (closer to original style)
"""

import socket
import ssl
import concurrent.futures
import time
import dns.resolver
import json
import os
import random
from datetime import datetime
from ipaddress import ip_address, IPv4Network, IPv6Network
from colorama import init, Fore, Style
import urllib3
import requests
import logging
from typing import List, Dict, Optional
import configparser
import argparse
import subprocess
import platform
import re
import signal
import threading
from timeit import default_timer as timer
import csv

try:
    from openpyxl import Workbook
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 5
MAX_RETRIES = 2
DEFAULT_MAX_WORKERS = 30
RATE_LIMIT_DELAY = 0.05

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


class CDNScannerPlus:
    def __init__(self, config_file: str = "config.ini"):
        self.config_file = config_file
        self._lock = threading.Lock()
        self._initialize_defaults()
        self._setup_infrastructure()
        self.load_config()
        self.setup_logging()

    def _initialize_defaults(self):
        self.gcore_test_domains = [
            "gcore.com", "www.gcore.com", "images.gcore.com",
            "static.gcore.com", "api.gcore.com", "cdn.gcdn.co",
            "cdn.gcorelabs.com", "demo-cdn.gcore.com"
        ]

        self.cdn_test_domains = {
            "cloudflare": ["www.cloudflare.com", "www.speedtest.net"],
            "fastly": ["fastly.net", "fastly.com"],
            "gcore": self.gcore_test_domains,
        }

        self.cdn_ranges = {
            "cloudflare": [
                "104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15",
                "108.162.192.0/18", "173.245.48.0/20", "141.101.64.0/18",
                "190.93.240.0/20", "188.114.96.0/20", "103.21.244.0/22",
                "103.22.200.0/22", "103.31.4.0/22", "198.41.128.0/17",
            ],
            "gcore": [
                "158.160.0.0/16", "92.223.84.0/24", "185.209.160.0/24",
                "45.133.144.0/24", "45.135.240.0/22", "45.159.216.0/22",
            ],
            "fastly": [
                "151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/32",
                "23.235.32.0/20", "43.249.72.0/22",
            ],
        }

        self.valid_pairs: List[Dict] = []
        self.scanned_domains = 0
        self.total_tests = 0
        self.start_time = None
        self.debug_mode = False
        self.verbose_mode = False
        self.rate_limit_delay = RATE_LIMIT_DELAY
        self.max_workers = DEFAULT_MAX_WORKERS
        self.dns_servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]
        self.output_dir = "results"
        self.proxies = None
        self.max_ping = 300
        self.enable_ws_probe = False  # set per-scan by user
        self._country_cache: Dict[str, str] = {}  # ip -> country name

    def _setup_infrastructure(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        adapter = requests.adapters.HTTPAdapter(pool_connections=30, pool_maxsize=30, max_retries=2)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def load_config(self) -> None:
        config = configparser.ConfigParser()
        config["DEFAULT"] = {
            "debug_mode": "False",
            "verbose_mode": "False",
            "rate_limit_delay": str(RATE_LIMIT_DELAY),
            "max_workers": str(DEFAULT_MAX_WORKERS),
            "dns_servers": ",".join(self.dns_servers),
            "output_dir": self.output_dir,
            "proxies": "",
            "max_ping": "300",
        }
        try:
            if os.path.exists(self.config_file):
                config.read(self.config_file)
            else:
                with open(self.config_file, "w") as f:
                    config.write(f)
                print(Fore.YELLOW + f"[*] Created default config: {self.config_file}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error loading config: {e}" + Style.RESET_ALL)
            return

        try:
            self.debug_mode = config.getboolean("DEFAULT", "debug_mode", fallback=False)
            self.verbose_mode = config.getboolean("DEFAULT", "verbose_mode", fallback=False)
            self.rate_limit_delay = config.getfloat("DEFAULT", "rate_limit_delay", fallback=RATE_LIMIT_DELAY)
            self.max_workers = config.getint("DEFAULT", "max_workers", fallback=DEFAULT_MAX_WORKERS)
            self.dns_servers = [s.strip() for s in config.get("DEFAULT", "dns_servers").split(",") if s.strip()]
            self.output_dir = config.get("DEFAULT", "output_dir", fallback="results")
            self.max_ping = config.getint("DEFAULT", "max_ping", fallback=300)
            proxy_str = config.get("DEFAULT", "proxies", fallback="")
            if proxy_str:
                self.configure_proxy(proxy_str)
            os.makedirs(self.output_dir, exist_ok=True)

            for cdn in list(self.cdn_ranges.keys()):
                filename = f"{cdn}.txt"
                if os.path.exists(filename):
                    try:
                        with open(filename, "r") as f:
                            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                            if lines:
                                self.cdn_ranges[cdn] = lines
                    except Exception as e:
                        print(Fore.RED + f"[!] Error loading {cdn} ranges: {e}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error applying config: {e}" + Style.RESET_ALL)

    def configure_proxy(self, proxy_url: str):
        self.proxies = {"http": proxy_url, "https": proxy_url}
        self.session.proxies = self.proxies

    def setup_logging(self) -> None:
        log_format = "%(asctime)s - %(levelname)s - %(message)s"
        level = logging.DEBUG if self.debug_mode else logging.INFO
        logging.basicConfig(
            level=level,
            format=log_format,
            filename=os.path.join(self.output_dir, "cdn_scanner.log"),
            filemode="a",
        )

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def clear_screen(self) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def print_banner(self) -> None:
        self.clear_screen()
        print(Fore.CYAN + r"""
   ____ ____  _   _   ____ ___ ____ _   _ _____ 
  / ___|  _ \| \ | | / ___|_ _/ ___| \ | |_   _|
 | |   | | | |  \| | \___ \| | |  _|  \| | | |  
 | |___| |_| | |\  |  ___) | | |_| | |\  | | |  
  \____|____/|_| \_| |____/___\____|_| \_| |_|  
        CDN SNI Scanner PLUS - Improved
        Dual HTTP/HTTPS + Optional WS Probe
        """ + Style.RESET_ALL)
        print(Fore.YELLOW + "VLESS+WS / VLESS+XHTTP / Xray | Optimized" + Style.RESET_ALL)

    def print_menu(self) -> None:
        self.print_banner()
        debug_status = f"{Fore.GREEN}●{Style.RESET_ALL}" if self.debug_mode else f"{Fore.RED}○{Style.RESET_ALL}"
        verbose_status = f"{Fore.GREEN}●{Style.RESET_ALL}" if self.verbose_mode else f"{Fore.RED}○{Style.RESET_ALL}"
        print(f"{debug_status} Debug | {verbose_status} Verbose | Workers: {self.max_workers} | Max Ping: {self.max_ping}ms | Proxy: {'ON' if self.proxies else 'OFF'}\n")

        print(Fore.YELLOW + "[1]" + Style.RESET_ALL + "  Scan single domain")
        print(Fore.YELLOW + "[2]" + Style.RESET_ALL + "  Scan random IPs (port 443 + HTTP 80)")
        print(Fore.YELLOW + "[3]" + Style.RESET_ALL + "  Scan domains from file")
        print(Fore.YELLOW + "[4]" + Style.RESET_ALL + "  View / filter results")
        print(Fore.YELLOW + "[5]" + Style.RESET_ALL + "  Toggle debug mode")
        print(Fore.YELLOW + "[6]" + Style.RESET_ALL + "  Test known CDN domains")
        print(Fore.YELLOW + "[7]" + Style.RESET_ALL + "  Deep CDN test")
        print(Fore.CYAN  + "[8]" + Style.RESET_ALL + "  Update CDN IP ranges")
        print(Fore.GREEN + "[9]" + Style.RESET_ALL + "  Xray / V2Ray compatibility test")
        print(Fore.GREEN + "[10]" + Style.RESET_ALL + " Multi-port scanner (Cloudflare)")
        print(Fore.GREEN + "[11]" + Style.RESET_ALL + " Generate VLESS config snippets")
        print(Fore.WHITE + "[12]" + Style.RESET_ALL + " Generate HTML report")
        print(Fore.WHITE + "[13]" + Style.RESET_ALL + " Export CSV / Excel")
        print(Fore.YELLOW + "[14]" + Style.RESET_ALL + " Configuration")
        print(Fore.RED   + "[0]"  + Style.RESET_ALL + "  Exit")
        print()

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------
    def resolve_domain(self, domain: str) -> List[str]:
        ips = set()
        for dns_server in self.dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.lifetime = 5
                for rtype in ("A", "AAAA"):
                    try:
                        answers = resolver.resolve(domain, rtype)
                        ips.update(str(r) for r in answers)
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                        continue
                if ips:
                    break
            except Exception as e:
                logging.warning(f"DNS failed ({dns_server}) for {domain}: {e}")
        return list(ips)

    def is_ip_in_cdn_ranges(self, ip: str, cdn_name: str) -> bool:
        try:
            ip_obj = ip_address(ip)
            for net in self.cdn_ranges.get(cdn_name.lower(), []):
                try:
                    if ip_obj.version == 4 and ip_obj in IPv4Network(net, strict=False):
                        return True
                    if ip_obj.version == 6 and ip_obj in IPv6Network(net, strict=False):
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            return False

    def get_ping(self, ip: str, count: int = 2) -> Optional[float]:
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            cmd = ["ping", param, str(count), "-W", "2", ip] if platform.system().lower() != "windows" else ["ping", param, str(count), ip]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
            if platform.system().lower() == "windows":
                m = re.search(r"Average = (\d+)ms", out)
            else:
                m = re.search(r"min/avg/max/[^=]+ = [\d.]+/([\d.]+)/", out)
            return float(m.group(1)) if m else None
        except Exception:
            return None

    def reverse_dns_lookup(self, ip: str) -> List[str]:
        try:
            host, aliases, _ = socket.gethostbyaddr(ip)
            return [host] + list(aliases)
        except Exception:
            return []

    def get_ip_country(self, ip: str) -> str:
        """Lookup country for an IP (cached). Uses free ip-api.com."""
        if ip in self._country_cache:
            return self._country_cache[ip]
        try:
            # Free endpoint, no API key needed. Rate limit ~45/min.
            resp = self.session.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode",
                timeout=4,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    country = data.get("country") or data.get("countryCode") or "Unknown"
                    self._country_cache[ip] = country
                    return country
        except Exception:
            pass
        self._country_cache[ip] = "Unknown"
        return "Unknown"

    # ------------------------------------------------------------------
    # HTTP (port 80) test
    # ------------------------------------------------------------------
    def test_http(self, ip: str, hostname: str, timeout: int = 4) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, 80))
            req = f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            resp = sock.recv(1024).decode(errors="ignore")
            sock.close()
            return "HTTP/" in resp
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Core HTTPS + optional WS probe
    # ------------------------------------------------------------------
    def test_sni_pair(self, ip: str, sni: str, timeout: int = DEFAULT_TIMEOUT, port: int = 443,
                      do_ws_probe: bool = False) -> Optional[Dict]:
        for attempt in range(MAX_RETRIES):
            try:
                return self._test_sni_pair(ip, sni, timeout, port, do_ws_probe)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    if self.debug_mode:
                        print(Fore.YELLOW + f"[DEBUG] {ip}:{port} / {sni} → {e}" + Style.RESET_ALL)
                    return None
                time.sleep(random.uniform(0.2, 0.5))
        return None

    def _test_sni_pair(self, ip: str, sni: str, timeout: int, port: int, do_ws_probe: bool) -> Optional[Dict]:
        with self._lock:
            self.total_tests += 1
        time.sleep(self.rate_limit_delay)

        result = {
            "ip": ip,
            "sni": sni,
            "port": port,
            "https_works": False,
            "http_works": False,
            "ws_upgrade": None,          # None = not tested, True/False = result
            "ping": None,
            "ssl_handshake_time": None,
            "server_header": None,
            "reverse_dns": [],
            "quality_score": 9999.0,
            "timestamp": datetime.now().isoformat(),
        }

        # ----- HTTPS test -----
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.settimeout(timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            start = timer()
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                result["ssl_handshake_time"] = round((timer() - start) * 1000, 1)

                # Basic HTTP response check
                try:
                    req = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {sni}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    ssock.sendall(req.encode())
                    resp = ssock.recv(2048).decode(errors="ignore")
                    if "HTTP/" in resp:
                        result["https_works"] = True
                        if "Server:" in resp:
                            result["server_header"] = resp.split("Server:")[1].split("\r\n")[0].strip()
                except Exception:
                    pass

                # Optional WebSocket upgrade probe (more realistic for VLESS+WS)
                if do_ws_probe and result["https_works"]:
                    try:
                        # New connection for clean WS probe
                        sock2 = socket.create_connection((ip, port), timeout=timeout)
                        sock2.settimeout(timeout)
                        with ctx.wrap_socket(sock2, server_hostname=sni) as ssock2:
                            ws_req = (
                                f"GET / HTTP/1.1\r\n"
                                f"Host: {sni}\r\n"
                                f"Upgrade: websocket\r\n"
                                f"Connection: Upgrade\r\n"
                                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                f"Sec-WebSocket-Version: 13\r\n"
                                f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                                f"\r\n"
                            )
                            ssock2.sendall(ws_req.encode())
                            ws_resp = ssock2.recv(1024).decode(errors="ignore")
                            # 101 Switching Protocols or any 4xx that still proves the edge is alive is useful
                            if "101" in ws_resp or "HTTP/" in ws_resp:
                                result["ws_upgrade"] = True
                            else:
                                result["ws_upgrade"] = False
                    except Exception:
                        result["ws_upgrade"] = False

        except Exception as e:
            if self.debug_mode:
                print(Fore.RED + f"[-] {ip}:{port} HTTPS failed: {e}" + Style.RESET_ALL)

        # ----- Always test plain HTTP on port 80 -----
        result["http_works"] = self.test_http(ip, sni)

        # We only keep the result if at least one protocol worked
        if not result["https_works"] and not result["http_works"]:
            return None

        result["ping"] = self.get_ping(ip)
        result["reverse_dns"] = self.reverse_dns_lookup(ip)

        # Quality score – prioritize HTTPS + low latency
        # WS success gives a small bonus
        ping = result["ping"] if result["ping"] is not None else 999
        hs = result["ssl_handshake_time"] if result["ssl_handshake_time"] is not None else 999
        score = ping * 0.65 + hs * 0.25
        if result["https_works"]:
            score -= 30          # strong bonus for working HTTPS
        if result.get("ws_upgrade") is True:
            score -= 15          # extra bonus for successful WS upgrade
        if not result["https_works"] and result["http_works"]:
            score += 80          # heavy penalty – only HTTP is usually not useful for VLESS TLS
        result["quality_score"] = round(max(score, 0), 1)

        return result

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------
    def _load_results(self, path: str) -> List[Dict]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            try:
                data = json.loads(content)
                return data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                results = []
                for line in content.splitlines():
                    line = line.strip().rstrip(",")
                    if not line or line in ("[", "]"):
                        continue
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        continue
                return results
        except Exception as e:
            print(Fore.RED + f"[!] Failed to load {path}: {e}" + Style.RESET_ALL)
            return []

    def _save_result(self, pair: Dict, output_file: str) -> None:
        try:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(pair, ensure_ascii=False) + "\n")
        except Exception as e:
            print(Fore.RED + f"[!] Save failed: {e}" + Style.RESET_ALL)

    def _deduplicate_and_rank(self, results: List[Dict]) -> List[Dict]:
        best = {}
        for r in results:
            key = (r.get("ip"), r.get("port", 443), r.get("sni"))
            score = r.get("quality_score", 9999)
            if key not in best or score < best[key].get("quality_score", 9999):
                best[key] = r
        return sorted(best.values(), key=lambda x: x.get("quality_score", 9999))

    def _filter_by_ping(self, results: List[Dict], max_ping: Optional[int] = None) -> List[Dict]:
        limit = max_ping if max_ping is not None else self.max_ping
        return [r for r in results if r.get("ping") is not None and r["ping"] <= limit]

    def _print_success(self, pair: Dict):
        ping = f"{pair['ping']}ms" if pair.get("ping") is not None else "N/A"
        hs = f"{pair.get('ssl_handshake_time', 'N/A')}ms"
        port = pair.get("port", 443)

        protocols = []
        if pair.get("https_works"):
            protocols.append("HTTPS")
        if pair.get("http_works"):
            protocols.append("HTTP")
        if pair.get("ws_upgrade") is True:
            protocols.append("WS")
        proto_str = "+".join(protocols) if protocols else "?"

        print(Fore.GREEN + f"[+] {pair['sni']} @ {pair['ip']}:{port} ({pair.get('cdn', '?')})  [{proto_str}]  Ping:{ping}  HS:{hs}" + Style.RESET_ALL)
        if pair.get("server_header"):
            print(Fore.CYAN + f"    Server: {pair['server_header']}" + Style.RESET_ALL)

    # ------------------------------------------------------------------
    # Scanning methods
    # ------------------------------------------------------------------
    def _ask_ws_probe(self) -> bool:
        ans = input(Fore.YELLOW + "Enable WebSocket upgrade probe? (more realistic for VLESS+WS, slightly slower) [y/N]: " + Style.RESET_ALL).strip().lower()
        return ans in ("y", "yes")

    def scan_domain(self, domain: str, output_file: Optional[str] = None, ports: Optional[List[int]] = None,
                    do_ws_probe: bool = False) -> List[Dict]:
        self.scanned_domains += 1
        print(Fore.GREEN + f"\n[*] Scanning {domain}" + Style.RESET_ALL)

        ips = self.resolve_domain(domain)
        if not ips:
            print(Fore.YELLOW + f"[!] No IPs for {domain}" + Style.RESET_ALL)
            return []

        ports = ports or [443]
        valid = []

        for cdn_name in self.cdn_ranges:
            cdn_ips = [ip for ip in ips if self.is_ip_in_cdn_ranges(ip, cdn_name)]
            if not cdn_ips:
                continue
            print(Fore.CYAN + f"[*] {len(cdn_ips)} {cdn_name} IP(s)" + Style.RESET_ALL)

            tasks = [(ip, domain, port) for ip in cdn_ips for port in ports]
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {
                    ex.submit(self.test_sni_pair, ip, domain, DEFAULT_TIMEOUT, port, do_ws_probe): (ip, port)
                    for ip, domain, port in tasks
                }
                for fut in concurrent.futures.as_completed(futures):
                    ip, port = futures[fut]
                    try:
                        res = fut.result()
                        if res:
                            pair = {**res, "cdn": cdn_name, "timestamp": datetime.now().isoformat()}
                            self._print_success(pair)
                            valid.append(pair)
                            if output_file:
                                self._save_result(pair, output_file)
                    except Exception as e:
                        if self.debug_mode:
                            print(Fore.RED + f"[!] {domain}@{ip}:{port} → {e}" + Style.RESET_ALL)
        return valid

    def generate_random_ips(self, cidr: str, count: int) -> List[str]:
        try:
            net = IPv4Network(cidr, strict=False)
            host_count = net.num_addresses
            if host_count <= 2:
                return [str(net.network_address)]
            return [str(net[random.randint(1, host_count - 2)]) for _ in range(count)]
        except ValueError:
            try:
                net = IPv6Network(cidr, strict=False)
                return [str(net[random.randint(0, min(net.num_addresses - 1, 2**32 - 1))]) for _ in range(count)]
            except ValueError:
                return []

    def scan_random_ips(self) -> None:
        self.print_banner()
        print(Fore.CYAN + "Random IP Scanner (HTTPS 443 + HTTP 80)\n" + Style.RESET_ALL)

        print("Select CDN:")
        cdns = list(self.cdn_ranges.keys())
        for i, c in enumerate(cdns, 1):
            print(f"  {i}. {c} ({len(self.cdn_ranges[c])} ranges)")
        try:
            choice = int(input("Choice: ").strip()) - 1
            cdn_name = cdns[choice]
        except Exception:
            print(Fore.RED + "[!] Invalid choice" + Style.RESET_ALL)
            time.sleep(1.5)
            return

        try:
            ip_count = int(input("How many IPs to test? (20-2000) [100]: ").strip() or "100")
            ip_count = max(20, min(2000, ip_count))
        except Exception:
            ip_count = 100

        sni = input("SNI hostname (e.g. www.speedtest.net / gcore.com / fastly.com OR fastly.net): ").strip()
        if not sni:
            print(Fore.RED + "[!] SNI required" + Style.RESET_ALL)
            time.sleep(1.5)
            return

        do_ws = self._ask_ws_probe()

        output_file = os.path.join(self.output_dir, "valid_pairs.json")

        print(Fore.YELLOW + f"\n[*] Generating ~{ip_count} random IPs from {cdn_name}..." + Style.RESET_ALL)
        all_ips = []
        per_range = max(1, ip_count // max(1, len(self.cdn_ranges[cdn_name])))
        for cidr in self.cdn_ranges[cdn_name]:
            all_ips.extend(self.generate_random_ips(cidr, per_range))
        random.shuffle(all_ips)
        test_ips = all_ips[:ip_count]

        print(Fore.YELLOW + f"[*] Testing {len(test_ips)} IPs  |  HTTPS:443 + HTTP:80  |  SNI={sni}" + Style.RESET_ALL)
        if do_ws:
            print(Fore.CYAN + "[*] WebSocket upgrade probe: ENABLED" + Style.RESET_ALL)
        else:
            print(Fore.CYAN + "[*] WebSocket upgrade probe: disabled" + Style.RESET_ALL)

        self.start_time = time.time()
        valid = []
        tasks = [(ip, sni) for ip in test_ips]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(self.test_sni_pair, ip, sni, DEFAULT_TIMEOUT, 443, do_ws): ip
                for ip, sni in tasks
            }
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                done += 1
                ip = futures[fut]
                try:
                    res = fut.result()
                    if res:
                        pair = {**res, "cdn": cdn_name, "timestamp": datetime.now().isoformat()}
                        self._print_success(pair)
                        valid.append(pair)
                        self._save_result(pair, output_file)
                except Exception:
                    pass

                if done % 15 == 0 or done == len(tasks):
                    elapsed = time.time() - self.start_time
                    print(Fore.CYAN + f"[*] Progress {done}/{len(tasks)} | Found {len(valid)} | {elapsed:.1f}s" + Style.RESET_ALL)

        ranked = self._deduplicate_and_rank(valid)
        filtered = self._filter_by_ping(ranked)

        elapsed = time.time() - self.start_time
        print(Fore.GREEN + f"\n[+] Finished in {elapsed:.1f}s" + Style.RESET_ALL)
        print(Fore.CYAN + f"    Raw hits : {len(valid)}" + Style.RESET_ALL)
        print(Fore.CYAN + f"    Unique   : {len(ranked)}" + Style.RESET_ALL)
        print(Fore.CYAN + f"    ≤{self.max_ping}ms : {len(filtered)}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Saved → {output_file}" + Style.RESET_ALL)
        input("\nPress Enter to continue...")

    def run_file_scan(self) -> None:
        self.print_banner()
        print(Fore.CYAN + "Batch Domain Scan\n" + Style.RESET_ALL)
        path = input("Path to domains file: ").strip()
        if not path or not os.path.exists(path):
            print(Fore.RED + "[!] File not found" + Style.RESET_ALL)
            time.sleep(1.5)
            return

        do_ws = self._ask_ws_probe()

        domains = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
        if not domains:
            print(Fore.RED + "[!] No domains" + Style.RESET_ALL)
            return

        output_file = os.path.join(self.output_dir, "valid_pairs.json")
        print(Fore.YELLOW + f"[*] Scanning {len(domains)} domains..." + Style.RESET_ALL)
        self.start_time = time.time()
        all_valid = []
        for d in domains:
            all_valid.extend(self.scan_domain(d, output_file, do_ws_probe=do_ws))
        print(Fore.GREEN + f"\n[+] Done in {time.time()-self.start_time:.1f}s — {len(all_valid)} hits" + Style.RESET_ALL)
        input("\nPress Enter...")

    def single_domain_scan(self) -> None:
        self.print_banner()
        print(Fore.CYAN + "Single Domain Scan\n" + Style.RESET_ALL)
        domain = input("Domain (e.g. example.com): ").strip()
        if not domain:
            return
        do_ws = self._ask_ws_probe()
        output_file = os.path.join(self.output_dir, "valid_pairs.json")
        self.start_time = time.time()
        valid = self.scan_domain(domain, output_file, do_ws_probe=do_ws)
        print(Fore.GREEN + f"\n[+] {len(valid)} valid pairs in {time.time()-self.start_time:.1f}s" + Style.RESET_ALL)
        input("\nPress Enter...")

    # ------------------------------------------------------------------
    # Multi-port
    # ------------------------------------------------------------------
    def scan_cloudflare_multiport(self) -> None:
        self.print_banner()
        print(Fore.GREEN + "--- Multi-Port CDN Scanner ---" + Style.RESET_ALL)

        files = {
            "1": ("valid_pairs.json", "Previous random / domain scan results"),
            "2": ("xray_working.json", "Previously Xray-tested results"),
        }
        available = {k: v for k, v in files.items() if os.path.exists(os.path.join(self.output_dir, v[0]))}

        print(Fore.CYAN + "\n[?] Source of IPs:")
        if available:
            for k, (fname, desc) in available.items():
                print(f"  {Fore.YELLOW}[{k}]{Style.RESET_ALL} {desc} ({fname})")
        else:
            print(Fore.RED + "  No previous result files found." + Style.RESET_ALL)
        print(f"  {Fore.YELLOW}[3]{Style.RESET_ALL} Generate new random Cloudflare IPs")

        choice = input("\nChoice (1-3): ").strip()
        test_ips: List[str] = []
        source_name = ""

        if choice in available:
            path = os.path.join(self.output_dir, available[choice][0])
            source_name = available[choice][0]
            data = self._load_results(path)
            for entry in data:
                ip = entry.get("ip") or entry.get("host")
                if ip:
                    test_ips.append(ip)
            test_ips = list(dict.fromkeys(test_ips))
        elif choice == "3" or not test_ips:
            source_name = "Cloudflare random ranges"
            if "cloudflare" in self.cdn_ranges:
                cidr = random.choice(self.cdn_ranges["cloudflare"])
                test_ips = self.generate_random_ips(cidr, 80)
            else:
                print(Fore.RED + "[!] No Cloudflare ranges" + Style.RESET_ALL)
                return

        if not test_ips:
            print(Fore.RED + "[!] No IPs to test" + Style.RESET_ALL)
            return

        print(Fore.CYAN + f"\n┌──────────────────────────────────────────────────────┐")
        print(f"│ SOURCE: {source_name:<20} │ IPs: {len(test_ips):<6} │")
        print(Fore.CYAN + "└──────────────────────────────────────────────────────┘" + Style.RESET_ALL)

        print(Fore.CYAN + "\n--- SNI Selection ---")
        print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} www.speedtest.net")
        print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} gcore.com")
        print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} fastly.com")
        print(f"{Fore.YELLOW}[4]{Style.RESET_ALL} fastly.net")
        print(f"{Fore.YELLOW}[5]{Style.RESET_ALL} Custom")
        sni_map = {"1": "www.speedtest.net", "2": "gcore.com", "3": "fastly.com", "4": "fastly.net"}
        sni_choice = input("Choice (1-5): ").strip()
        sni = sni_map.get(sni_choice) or input("Custom SNI: ").strip() or "www.speedtest.net"

        port_input = input("\nPorts (e.g. 443,2053,2083 or 'all'): ").strip().lower()
        if port_input in ("all", ""):
            selected_ports = CF_HTTPS_PORTS
        else:
            try:
                selected_ports = [int(p.strip()) for p in port_input.split(",") if p.strip()]
            except Exception:
                selected_ports = [443]

        do_ws = self._ask_ws_probe()

        print(Fore.CYAN + f"\n[*] Scanning {len(test_ips)} IPs × {len(selected_ports)} ports | SNI={sni}" + Style.RESET_ALL)

        txt_file = os.path.join(self.output_dir, "multiport_results.txt")
        json_file = os.path.join(self.output_dir, "multiport_results.json")
        found = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            futures = {
                ex.submit(self.test_sni_pair, ip, sni, 7, port, do_ws): (ip, port)
                for ip in test_ips for port in selected_ports
            }
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    ip, port = res["ip"], res["port"]
                    protocols = []
                    if res.get("https_works"):
                        protocols.append("HTTPS")
                    if res.get("http_works"):
                        protocols.append("HTTP")
                    if res.get("ws_upgrade") is True:
                        protocols.append("WS")
                    print(Fore.GREEN + f" [+] {ip}:{port}  [{'+'.join(protocols)}]  Ping:{res.get('ping')}ms" + Style.RESET_ALL)
                    found.append(res)
                    with open(txt_file, "a", encoding="utf-8") as f:
                        f.write(f"{ip}:{port} | SNI:{sni} | {protocols} | Ping:{res.get('ping')}ms\n")

        ranked = self._deduplicate_and_rank(found)
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(ranked, f, indent=2, ensure_ascii=False)

        print(Fore.YELLOW + f"\n[*] Done. {len(ranked)} unique endpoints.")
        print(Fore.YELLOW + f"    {txt_file}")
        print(Fore.YELLOW + f"    {json_file}")
        input("\nPress Enter...")

    # ------------------------------------------------------------------
    # Xray test
    # ------------------------------------------------------------------
    def test_xray_connection(self, ip: str, sni: str, port: int = 443, timeout: int = 5) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((ip, port), timeout=timeout)
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                req = f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                ssock.send(req.encode())
                resp = ssock.recv(1024)
                return b"HTTP/" in resp or b"403" in resp or b"404" in resp
        except Exception:
            return False

    def xray_test_menu(self) -> None:
        self.print_banner()
        print(Fore.CYAN + "Xray / V2Ray Compatibility Test\n" + Style.RESET_ALL)

        # Let user choose which result file to test
        candidates = {
            "1": ("valid_pairs.json", "Random / domain scan results"),
            "2": ("multiport_results.json", "Multi-port scanner results"),
            "3": ("xray_working.json", "Previously Xray-tested results"),
        }
        available = {k: v for k, v in candidates.items()
                     if os.path.exists(os.path.join(self.output_dir, v[0]))}

        if not available:
            print(Fore.RED + "[!] No result files found. Run a scan first." + Style.RESET_ALL)
            input("\nPress Enter...")
            return

        print(Fore.CYAN + "Select source to test:")
        for k, (fname, desc) in available.items():
            print(f"  {Fore.YELLOW}[{k}]{Style.RESET_ALL} {desc} ({fname})")
        choice = input("\nChoice: ").strip()
        if choice not in available:
            print(Fore.RED + "[!] Invalid choice" + Style.RESET_ALL)
            time.sleep(1)
            return

        results_file = os.path.join(self.output_dir, available[choice][0])
        results = self._load_results(results_file)
        if not results:
            print(Fore.RED + "[!] File is empty" + Style.RESET_ALL)
            input("\nPress Enter...")
            return

        print(Fore.GREEN + f"[*] Testing {len(results)} entries from {available[choice][0]}..." + Style.RESET_ALL)
        working = []
        for i, r in enumerate(results, 1):
            ip = r.get("ip")
            sni = r.get("sni")
            port = r.get("port", 443)
            if not ip or not sni:
                continue
            ok = self.test_xray_connection(ip, sni, port)
            r["xray_works"] = ok
            status = Fore.GREEN + "WORKING" if ok else Fore.RED + "FAILED"
            print(f"[{i}/{len(results)}] {sni} @ {ip}:{port} → {status}{Style.RESET_ALL}")
            if ok:
                working.append(r)

        # Write xray_works flag back into the source file so HTML report shows correct ✓/✗
        try:
            with open(results_file, "w", encoding="utf-8") as f:
                # Keep original format style (NDJSON for valid_pairs, pretty JSON for others)
                if results_file.endswith("valid_pairs.json"):
                    for r in results:
                        f.write(json.dumps(r, ensure_ascii=False) + "\n")
                else:
                    json.dump(results, f, indent=2, ensure_ascii=False)
            print(Fore.CYAN + f"[*] Updated {results_file} with Xray results" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Could not update source file: {e}" + Style.RESET_ALL)

        if working:
            xray_json = os.path.join(self.output_dir, "xray_working.json")
            xray_txt = os.path.join(self.output_dir, "xray_working.txt")
            with open(xray_json, "w", encoding="utf-8") as f:
                json.dump(working, f, indent=2, ensure_ascii=False)
            with open(xray_txt, "w", encoding="utf-8") as f:
                for item in working:
                    f.write(f"{item['ip']}:{item.get('port',443)} | {item['sni']} | Ping:{item.get('ping','N/A')}ms\n")
            print(Fore.GREEN + f"\n[+] {len(working)} Xray-compatible endpoints saved." + Style.RESET_ALL)
            print(Fore.GREEN + f"    {xray_json}" + Style.RESET_ALL)
            print(Fore.GREEN + f"    {xray_txt}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "\n[!] No Xray-compatible results" + Style.RESET_ALL)
        input("\nPress Enter...")

    # ------------------------------------------------------------------
    # VLESS snippets (plain links only – Host and SNI are separate)
    # ------------------------------------------------------------------
    def generate_vless_snippets(self) -> None:
        self.print_banner()
        print(Fore.CYAN + "VLESS Link Generator (WS / XHTTP)\n" + Style.RESET_ALL)

        candidates = [
            os.path.join(self.output_dir, "multiport_results.json"),
            os.path.join(self.output_dir, "xray_working.json"),
            os.path.join(self.output_dir, "valid_pairs.json"),
        ]
        results = []
        used_file = None
        for path in candidates:
            results = self._load_results(path)
            if results:
                used_file = path
                break
        if not results:
            print(Fore.RED + "[!] No usable results found." + Style.RESET_ALL)
            input("\nPress Enter...")
            return

        ranked = self._deduplicate_and_rank(results)
        ranked = [r for r in ranked if r.get("https_works")] or ranked
        filtered = self._filter_by_ping(ranked) or ranked[:30]

        print(Fore.GREEN + f"[*] Using {used_file} → {len(filtered)} candidates\n" + Style.RESET_ALL)

        uuid = input("Your UUID: ").strip() or "YOUR-UUID-HERE"
        path = input("Path (e.g. / or /ray or /xhttp) [/]: ").strip() or "/"
        sni = input("SNI (e.g. www.speedtest.net): ").strip()
        host = input("Host (can be different from SNI): ").strip()

        if not sni:
            sni = "www.speedtest.net"
        if not host:
            host = sni

        out_file = os.path.join(self.output_dir, "vless_snippets.txt")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("# VLESS plain links - CDN Scanner Plus\n")
            f.write(f"# Source: {used_file}\n")
            f.write(f"# SNI: {sni}  |  Host: {host}  |  Path: {path}\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")

            for i, r in enumerate(filtered[:40], 1):
                ip = r["ip"]
                port = r.get("port", 443)
                ping = r.get("ping", "N/A")
                score = r.get("quality_score", "N/A")

                # Plain VLESS link – Host and SNI are separate
                link = (
                    f"vless://{uuid}@{ip}:{port}"
                    f"?encryption=none&security=tls&sni={sni}"
                    f"&type=ws&host={host}&path={path}"
                    f"#{ip}:{port}-ping{ping}"
                )
                f.write(f"# #{i}  Ping:{ping}ms  Score:{score}\n")
                f.write(link + "\n\n")
                print(Fore.GREEN + f"[{i}] {ip}:{port}  Ping={ping}ms" + Style.RESET_ALL)

        print(Fore.YELLOW + f"\n[+] Plain VLESS links written to {out_file}" + Style.RESET_ALL)
        input("\nPress Enter...")

    # ------------------------------------------------------------------
    # View / Reports
    # ------------------------------------------------------------------
    def view_results(self) -> None:
        self.print_banner()
        results_file = os.path.join(self.output_dir, "valid_pairs.json")
        results = self._load_results(results_file)
        if not results:
            print(Fore.RED + "[!] No results file" + Style.RESET_ALL)
            input("\nPress Enter...")
            return

        ranked = self._deduplicate_and_rank(results)
        filtered = self._filter_by_ping(ranked)
        print(Fore.CYAN + f"\nTotal unique: {len(ranked)} | ≤{self.max_ping}ms: {len(filtered)}\n" + Style.RESET_ALL)

        show = filtered if filtered else ranked
        for i, p in enumerate(show[:50], 1):
            protocols = []
            if p.get("https_works"):
                protocols.append("HTTPS")
            if p.get("http_works"):
                protocols.append("HTTP")
            if p.get("ws_upgrade") is True:
                protocols.append("WS")
            if p.get("xray_works"):
                protocols.append("Xray")
            proto = "+".join(protocols) or "?"
            ping = f"{p.get('ping', 'N/A')}ms"
            print(f"{i:2d}. {p.get('sni')} @ {p.get('ip')}:{p.get('port',443)} ({p.get('cdn','?')})")
            print(f"     [{proto}] | Ping {ping} | Score {p.get('quality_score','?')} | Server: {p.get('server_header','N/A')}")

        if len(show) > 50:
            print(Fore.YELLOW + f"\n... and {len(show)-50} more" + Style.RESET_ALL)
        if input("\nSave filtered ranked list as TXT? (y/n): ").lower() == "y":
            txt = results_file.replace(".json", "_ranked.txt")
            self.save_to_txt(show, txt)
        input("\nPress Enter...")

    def save_to_txt(self, results: List[Dict], filename: str) -> None:
        try:
            with open(filename, "w", encoding="utf-8") as f:
                for r in results:
                    f.write(f"IP: {r.get('ip')}\n")
                    f.write(f"Port: {r.get('port', 443)}\n")
                    f.write(f"SNI: {r.get('sni')}\n")
                    f.write(f"CDN: {r.get('cdn', 'N/A')}\n")
                    f.write(f"HTTPS: {'Yes' if r.get('https_works') else 'No'}\n")
                    f.write(f"HTTP : {'Yes' if r.get('http_works') else 'No'}\n")
                    f.write(f"WS Upgrade: {r.get('ws_upgrade')}\n")
                    f.write(f"Ping: {r.get('ping', 'N/A')}ms\n")
                    f.write(f"SSL Handshake: {r.get('ssl_handshake_time', 'N/A')}ms\n")
                    f.write(f"Quality Score: {r.get('quality_score', 'N/A')}\n")
                    f.write(f"Server: {r.get('server_header', 'N/A')}\n")
                    f.write("-" * 40 + "\n")
            print(Fore.GREEN + f"[+] Saved {filename}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] {e}" + Style.RESET_ALL)

    def generate_html_report(self) -> None:
        results_file = os.path.join(self.output_dir, "valid_pairs.json")
        results = self._load_results(results_file)
        if not results:
            print(Fore.RED + "[!] No results" + Style.RESET_ALL)
            input("\nPress Enter...")
            return
        ranked = self._deduplicate_and_rank(results)

        # Optional country lookup
        do_geo = input(Fore.YELLOW + "Lookup IP countries? (needs internet, a bit slower) [y/N]: " + Style.RESET_ALL).strip().lower()
        if do_geo in ("y", "yes"):
            print(Fore.CYAN + "[*] Looking up IP countries..." + Style.RESET_ALL)
            unique_ips = list({r.get("ip") for r in ranked if r.get("ip")})
            for i, ip in enumerate(unique_ips, 1):
                country = self.get_ip_country(ip)
                if i % 10 == 0 or i == len(unique_ips):
                    print(Fore.CYAN + f"    {i}/{len(unique_ips)} IPs..." + Style.RESET_ALL)
                time.sleep(0.35)  # stay under free API rate limit
                for r in ranked:
                    if r.get("ip") == ip:
                        r["country"] = country
        else:
            print(Fore.CYAN + "[*] Skipping country lookup" + Style.RESET_ALL)

        html_file = os.path.join(self.output_dir, "report.html")
        self._write_html(ranked, html_file)
        print(Fore.GREEN + f"[+] HTML report → {html_file}" + Style.RESET_ALL)
        input("\nPress Enter...")

    def _write_html(self, results: List[Dict], filename: str) -> None:
        """Colorful but clean report closer to original style + Country column."""
        rows = ""
        for r in results:
            ping = r.get("ping", "N/A")
            hs = r.get("ssl_handshake_time", "N/A")
            score = r.get("quality_score", "N/A")
            country = r.get("country") or "–"
            https = '<span class="good">✓</span>' if r.get("https_works") else '<span class="bad">✗</span>'
            http = '<span class="good">✓</span>' if r.get("http_works") else '<span class="bad">✗</span>'
            ws = r.get("ws_upgrade")
            if ws is True:
                ws_cell = '<span class="good">✓</span>'
            elif ws is False:
                ws_cell = '<span class="bad">✗</span>'
            else:
                ws_cell = '<span class="na">–</span>'
            xray = '<span class="good">✓</span>' if r.get("xray_works") else '<span class="bad">✗</span>'

            rows += f"""
            <tr>
                <td class="copyable">{r.get('ip')}</td>
                <td>{r.get('port',443)}</td>
                <td class="copyable">{r.get('sni')}</td>
                <td>{r.get('cdn','')}</td>
                <td>{country}</td>
                <td>{https}</td>
                <td>{http}</td>
                <td>{ws_cell}</td>
                <td>{xray}</td>
                <td>{ping}</td>
                <td>{hs}</td>
                <td>{score}</td>
                <td>{r.get('server_header','')}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CDN Scanner Report By Jeet</title>
    <style>
        body {{
            font-family: Arial, Helvetica, sans-serif;
            margin: 20px;
            background: #f5f7fa;
            color: #222;
        }}
        h1 {{
            color: #1a73e8;
            margin-bottom: 4px;
        }}
        .meta {{
            color: #555;
            margin-bottom: 18px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            border: 1px solid #e0e0e0;
            padding: 10px 12px;
            text-align: left;
            font-size: 14px;
        }}
        th {{
            background: #1a73e8;
            color: white;
            cursor: pointer;
            position: sticky;
            top: 0;
            user-select: none;
        }}
        th:hover {{
            background: #1557b0;
        }}
        tr:nth-child(even) {{
            background: #f8fafc;
        }}
        tr:hover {{
            background: #e8f0fe;
        }}
        .good {{ color: #0d904f; font-weight: bold; }}
        .bad  {{ color: #d93025; font-weight: bold; }}
        .na   {{ color: #9aa0a6; }}
        .copyable {{
            cursor: pointer;
            color: #1a73e8;
        }}
        .copyable:hover {{
            text-decoration: underline;
        }}
        .copy-tooltip {{
            position: absolute;
            bottom: calc(100% + 6px);
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: #fff;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            white-space: nowrap;
            z-index: 100;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }}
    </style>
</head>
<body>
    <h1>CDN Scanner Report</h1>
    <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Total unique: {len(results)} &nbsp;|&nbsp; Sorted by quality score</p>

    <table id="resultsTable">
        <thead>
            <tr>
                <th onclick="sortTable(0)">IP</th>
                <th onclick="sortTable(1)">Port</th>
                <th onclick="sortTable(2)">SNI</th>
                <th onclick="sortTable(3)">CDN</th>
                <th onclick="sortTable(4)">Country</th>
                <th onclick="sortTable(5)">HTTPS</th>
                <th onclick="sortTable(6)">HTTP</th>
                <th onclick="sortTable(7)">WS</th>
                <th onclick="sortTable(8)">Xray</th>
                <th onclick="sortTable(9)">Ping (ms)</th>
                <th onclick="sortTable(10)">HS (ms)</th>
                <th onclick="sortTable(11)">Score</th>
                <th onclick="sortTable(12)">Server</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    <script>
        document.querySelectorAll('.copyable').forEach(td => {{
            td.title = 'Click to copy';
            td.addEventListener('click', () => {{
                navigator.clipboard.writeText(td.textContent.trim());
                const tip = document.createElement('div');
                tip.className = 'copy-tooltip';
                tip.textContent = 'Copied!';
                td.style.position = 'relative';
                td.appendChild(tip);
                setTimeout(() => tip.remove(), 900);
            }});
        }});

        function sortTable(column) {{
            const table = document.getElementById("resultsTable");
            const rows = Array.from(table.rows).slice(1);
            const header = table.rows[0].cells[column];
            const direction = header.getAttribute("data-direction") || "asc";

            rows.sort((a, b) => {{
                let aVal = a.cells[column].textContent.trim();
                let bVal = b.cells[column].textContent.trim();
                // strip symbols for sorting
                aVal = aVal.replace(/[✓✗–]/g, '').trim();
                bVal = bVal.replace(/[✓✗–]/g, '').trim();
                if (!isNaN(aVal) && !isNaN(bVal) && aVal !== '' && bVal !== '') {{
                    return direction === "asc" ? aVal - bVal : bVal - aVal;
                }}
                return direction === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            }});

            rows.forEach(row => table.tBodies[0].appendChild(row));
            header.setAttribute("data-direction", direction === "asc" ? "desc" : "asc");
        }}
    </script>
</body>
</html>"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

    def export_menu(self) -> None:
        results_file = os.path.join(self.output_dir, "valid_pairs.json")
        results = self._load_results(results_file)
        if not results:
            print(Fore.RED + "[!] No results" + Style.RESET_ALL)
            input("\nPress Enter...")
            return
        ranked = self._deduplicate_and_rank(results)
        print("\n1. CSV\n2. Excel\n3. Both")
        choice = input("Choice: ").strip()
        if choice in ("1", "3"):
            self.export_to_csv(ranked, os.path.join(self.output_dir, "cdn_results.csv"))
        if choice in ("2", "3"):
            self.export_to_excel(ranked, os.path.join(self.output_dir, "cdn_results.xlsx"))
        input("\nPress Enter...")

    def export_to_csv(self, results: List[Dict], filename: str) -> None:
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                fields = ["ip", "port", "sni", "cdn", "country", "https_works", "http_works", "ws_upgrade",
                          "xray_works", "ping", "ssl_handshake_time", "quality_score", "server_header", "timestamp"]
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                for r in results:
                    row = {k: r.get(k, "") for k in fields}
                    row["https_works"] = "Yes" if r.get("https_works") else "No"
                    row["http_works"] = "Yes" if r.get("http_works") else "No"
                    row["xray_works"] = "Yes" if r.get("xray_works") else "No"
                    w.writerow(row)
            print(Fore.GREEN + f"[+] CSV → {filename}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] {e}" + Style.RESET_ALL)

    def export_to_excel(self, results: List[Dict], filename: str) -> None:
        if not HAS_OPENPYXL:
            print(Fore.RED + "[!] openpyxl not installed (pip install openpyxl)" + Style.RESET_ALL)
            return
        try:
            wb = Workbook()
            ws = wb.active
            ws.title = "CDN Results"
            headers = ["IP", "Port", "SNI", "CDN", "Country", "HTTPS", "HTTP", "WS", "Xray",
                       "Ping", "HS (ms)", "Score", "Server", "Timestamp"]
            ws.append(headers)
            for r in results:
                ws.append([
                    r.get("ip"), r.get("port", 443), r.get("sni"), r.get("cdn"),
                    r.get("country", ""),
                    "Yes" if r.get("https_works") else "No",
                    "Yes" if r.get("http_works") else "No",
                    r.get("ws_upgrade"),
                    "Yes" if r.get("xray_works") else "No",
                    r.get("ping"), r.get("ssl_handshake_time"), r.get("quality_score"),
                    r.get("server_header"), r.get("timestamp"),
                ])
            wb.save(filename)
            print(Fore.GREEN + f"[+] Excel → {filename}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] {e}" + Style.RESET_ALL)

    # ------------------------------------------------------------------
    # Range update + config
    # ------------------------------------------------------------------
    def update_cdn_ranges(self) -> None:
        sources = {
            "cloudflare": {"url": "https://www.cloudflare.com/ips-v4", "fallback": self.cdn_ranges.get("cloudflare", [])},
            "gcore": {"url": "https://api.gcore.com/cdn/public-ip-list", "fallback": self.cdn_ranges.get("gcore", []), "alt": "https://cdn.gcorelabs.com/ip-list.txt"},
            "fastly": {"url": "https://api.fastly.com/public-ip-list", "fallback": self.cdn_ranges.get("fastly", []), "alt": "https://ip-ranges.fastly.com/"},
        }
        print(Fore.YELLOW + "\n[*] Updating CDN ranges (use VPN if needed)..." + Style.RESET_ALL)
        for cdn, src in sources.items():
            ranges = []
            ok = False
            try:
                print(Fore.CYAN + f"[*] {cdn} primary..." + Style.RESET_ALL)
                resp = self.session.get(src["url"], timeout=15)
                resp.raise_for_status()
                if cdn == "cloudflare":
                    ranges = [l.strip() for l in resp.text.splitlines() if l.strip()]
                elif cdn == "gcore":
                    data = resp.json()
                    ranges = data.get("addresses", []) + data.get("prefixes", [])
                elif cdn == "fastly":
                    data = resp.json()
                    ranges = data.get("addresses", [])
                ok = True
                print(Fore.GREEN + f"[+] {cdn} updated from primary" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.YELLOW + f"[!] Primary failed ({e})" + Style.RESET_ALL)
                if "alt" in src:
                    try:
                        alt = self.session.get(src["alt"], timeout=15)
                        alt.raise_for_status()
                        ranges = [l.strip() for l in alt.text.splitlines() if l.strip() and not l.startswith("#")]
                        ok = True
                        print(Fore.GREEN + f"[+] {cdn} updated from alternative" + Style.RESET_ALL)
                    except Exception as e2:
                        print(Fore.YELLOW + f"[!] Alt also failed ({e2})" + Style.RESET_ALL)
            if not ok:
                ranges = src["fallback"]
                print(Fore.YELLOW + f"[!] Using fallback for {cdn}" + Style.RESET_ALL)
            with open(f"{cdn}.txt", "w") as f:
                f.write("\n".join(ranges))
            self.cdn_ranges[cdn] = ranges
            print(Fore.GREEN + f"[+] {cdn}: {len(ranges)} ranges" + Style.RESET_ALL)
        self.save_config()
        input("\nPress Enter...")

    def edit_configuration(self) -> None:
        while True:
            self.print_banner()
            print(Fore.CYAN + "Configuration\n" + Style.RESET_ALL)
            print(f"1. Debug mode          : {self.debug_mode}")
            print(f"2. Verbose mode        : {self.verbose_mode}")
            print(f"3. Rate limit delay    : {self.rate_limit_delay}s")
            print(f"4. Max workers         : {self.max_workers}")
            print(f"5. Max ping filter     : {self.max_ping}ms")
            print(f"6. DNS servers         : {', '.join(self.dns_servers)}")
            print(f"7. Output directory    : {self.output_dir}")
            print(f"8. Proxy               : {self.proxies.get('http') if self.proxies else 'None'}")
            print("9. Save & return")
            print("0. Return without saving")
            c = input("\nChoice: ").strip()
            if c == "1":
                self.debug_mode = not self.debug_mode
            elif c == "2":
                self.verbose_mode = not self.verbose_mode
            elif c == "3":
                try:
                    v = float(input("New delay (0-2): "))
                    if 0 <= v <= 2:
                        self.rate_limit_delay = v
                except Exception:
                    pass
            elif c == "4":
                try:
                    v = int(input("New max workers (5-100): "))
                    self.max_workers = max(5, min(100, v))
                except Exception:
                    pass
            elif c == "5":
                try:
                    v = int(input("New max ping ms (50-1000): "))
                    self.max_ping = max(50, min(1000, v))
                except Exception:
                    pass
            elif c == "6":
                s = input("Comma-separated DNS servers: ").strip()
                if s:
                    self.dns_servers = [x.strip() for x in s.split(",") if x.strip()]
            elif c == "7":
                d = input("New output dir: ").strip()
                if d:
                    self.output_dir = d
                    os.makedirs(d, exist_ok=True)
            elif c == "8":
                p = input("Proxy URL (empty to disable): ").strip()
                if p:
                    self.configure_proxy(p)
                else:
                    self.proxies = None
                    self.session.proxies = {}
            elif c == "9":
                self.save_config()
                print(Fore.GREEN + "[+] Saved" + Style.RESET_ALL)
                time.sleep(0.8)
                return
            elif c == "0":
                return

    def save_config(self) -> None:
        config = configparser.ConfigParser()
        config["DEFAULT"] = {
            "debug_mode": str(self.debug_mode),
            "verbose_mode": str(self.verbose_mode),
            "rate_limit_delay": str(self.rate_limit_delay),
            "max_workers": str(self.max_workers),
            "dns_servers": ",".join(self.dns_servers),
            "output_dir": self.output_dir,
            "proxies": self.proxies.get("http") if self.proxies else "",
            "max_ping": str(self.max_ping),
        }
        try:
            with open(self.config_file, "w") as f:
                config.write(f)
        except Exception as e:
            print(Fore.RED + f"[!] Save config failed: {e}" + Style.RESET_ALL)

    def test_known_cdns(self) -> None:
        print(Fore.CYAN + "\n[*] Testing known CDN domains..." + Style.RESET_ALL)
        do_ws = self._ask_ws_probe()
        self.start_time = time.time()
        all_res = []
        for cdn, domains in self.cdn_test_domains.items():
            for d in domains:
                print(Fore.YELLOW + f"\n[*] {d} (expect {cdn})" + Style.RESET_ALL)
                pairs = self.scan_domain(d, do_ws_probe=do_ws)
                all_res.extend(pairs)
        if all_res:
            path = os.path.join(self.output_dir, "known_cdn_results.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(all_res, f, indent=2, ensure_ascii=False)
            print(Fore.GREEN + f"\n[+] Saved {path}" + Style.RESET_ALL)
        print(Fore.CYAN + f"[*] Done in {time.time()-self.start_time:.1f}s" + Style.RESET_ALL)
        input("\nPress Enter...")

    def test_specific_cdn(self) -> None:
        self.print_banner()
        print(Fore.CYAN + "Deep CDN Test\n" + Style.RESET_ALL)
        cdns = list(self.cdn_test_domains.keys())
        for i, c in enumerate(cdns, 1):
            print(f"  {i}. {c}")
        try:
            choice = int(input("Choice: ").strip()) - 1
            cdn = cdns[choice]
        except Exception:
            return
        do_ws = self._ask_ws_probe()
        out = os.path.join(self.output_dir, f"{cdn}_results.json")
        all_res = []
        for d in self.cdn_test_domains[cdn]:
            print(Fore.YELLOW + f"\n[*] {d}" + Style.RESET_ALL)
            ips = self.resolve_domain(d)
            print(Fore.CYAN + f"    IPs: {ips}" + Style.RESET_ALL)
            for ip in ips:
                res = self.test_sni_pair(ip, d, do_ws_probe=do_ws)
                if res:
                    pair = {**res, "cdn": cdn, "timestamp": datetime.now().isoformat()}
                    self._print_success(pair)
                    all_res.append(pair)
                else:
                    print(Fore.RED + f"    [-] {ip} failed" + Style.RESET_ALL)
        if all_res:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(all_res, f, indent=2, ensure_ascii=False)
            print(Fore.GREEN + f"\n[+] Saved {out}" + Style.RESET_ALL)
        input("\nPress Enter...")

    def _handle_sigint(self, signum, frame):
        print(Fore.RED + "\n[!] Interrupted" + Style.RESET_ALL)
        raise KeyboardInterrupt

    def run(self) -> None:
        parser = argparse.ArgumentParser(description="CDN SNI Scanner PLUS - Dual + Optional WS")
        parser.add_argument("-d", "--debug", action="store_true")
        parser.add_argument("-v", "--verbose", action="store_true")
        parser.add_argument("-c", "--config", help="Config file")
        parser.add_argument("-p", "--proxy", help="Proxy URL")
        parser.add_argument("--workers", type=int, help="Max workers")
        args = parser.parse_args()

        if args.config:
            self.config_file = args.config
        if args.debug:
            self.debug_mode = True
        if args.verbose:
            self.verbose_mode = True
        if args.proxy:
            self.configure_proxy(args.proxy)
        if args.workers:
            self.max_workers = max(5, min(100, args.workers))

        self.load_config()
        self.setup_logging()
        signal.signal(signal.SIGINT, self._handle_sigint)

        while True:
            try:
                self.print_menu()
                choice = input("Select (0-14): ").strip()
                if choice == "1":
                    self.single_domain_scan()
                elif choice == "2":
                    self.scan_random_ips()
                elif choice == "3":
                    self.run_file_scan()
                elif choice == "4":
                    self.view_results()
                elif choice == "5":
                    self.debug_mode = not self.debug_mode
                    print(Fore.YELLOW + f"Debug: {'ON' if self.debug_mode else 'OFF'}" + Style.RESET_ALL)
                    time.sleep(0.8)
                elif choice == "6":
                    self.test_known_cdns()
                elif choice == "7":
                    self.test_specific_cdn()
                elif choice == "8":
                    self.update_cdn_ranges()
                elif choice == "9":
                    self.xray_test_menu()
                elif choice == "10":
                    self.scan_cloudflare_multiport()
                elif choice == "11":
                    self.generate_vless_snippets()
                elif choice == "12":
                    self.generate_html_report()
                elif choice == "13":
                    self.export_menu()
                elif choice == "14":
                    self.edit_configuration()
                elif choice == "0":
                    print(Fore.CYAN + "\n[+] Bye" + Style.RESET_ALL)
                    break
                else:
                    print(Fore.RED + "[!] Invalid" + Style.RESET_ALL)
                    time.sleep(0.8)
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] Cancelled" + Style.RESET_ALL)
                break
            except Exception as e:
                logging.exception("Unexpected error")
                print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)
                time.sleep(1.5)


if __name__ == "__main__":
    try:
        scanner = CDNScannerPlus()
        scanner.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Terminated" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Fatal: {e}" + Style.RESET_ALL)
        input("Press Enter to exit...")
