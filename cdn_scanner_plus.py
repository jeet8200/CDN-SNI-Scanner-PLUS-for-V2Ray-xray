#!/usr/bin/env python3
import socket
import ssl
import concurrent.futures
import time
import dns.resolver
import json
import os
import random
from datetime import datetime
from ipaddress import ip_address, ip_network, IPv4Network, IPv6Network
from colorama import init, Fore, Back, Style
import urllib3
import requests
import logging
from typing import List, Dict, Tuple, Optional, Union, Any
import configparser
import argparse
import subprocess
import platform
import re
import shutil
from timeit import default_timer as timer
import csv
import signal



# ConstantS
DEFAULT_TIMEOUT = 5
MAX_RETRIES = 3
MAX_WORKERS = 20
RATE_LIMIT_DELAY = 0.1  # seconds between requests

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for Windows console colors
init(autoreset=True)
# Cloudflare HTTPS Ports
CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
class CDNScannerPlus:
    def __init__(self, config_file: str = 'config.ini'):
        self.config_file = config_file
        self._initialize_defaults()
        self._setup_infrastructure()
        self.load_config()
        self.setup_logging()
        
    def _initialize_defaults(self):
        """Initialize all default values"""
        self.gcore_test_domains = [
            'gcore.com', 'www.gcore.com', 'images.gcore.com',
            'static.gcore.com', 'api.gcore.com', 'cdn.gcdn.co',
            'cdn.gcorelabs.com', 'demo-cdn.gcore.com'
        ]
        
        self.cdn_test_domains = {
            'cloudflare': ['www.cloudflare.com', 'www.speedtest.net'],
            'fastly': ['fastly.net', 'fastly.com'],
            'gcore': self.gcore_test_domains
        }

        self.cdn_ranges = {
            'cloudflare': [
                '104.16.0.0/13', '172.64.0.0/13', '162.158.0.0/15', 
                '108.162.192.0/18', '173.245.48.0/20', '141.101.64.0/18',
                '190.93.240.0/20', '188.114.96.0/20'
            ],
            'gcore': [
                '158.160.0.0/16', '92.223.84.0/24', '185.209.160.0/24',
                '45.133.144.0/24', '45.135.240.0/22', '45.159.216.0/22'
            ],
            'fastly': [
                '151.101.0.0/16', '199.232.0.0/16', '2a04:4e40::/32',
                '23.235.32.0/20', '43.249.72.0/22'
            ]
        }

        self.valid_pairs = []
        self.scanned_domains = 0
        self.total_tests = 0
        self.start_time = None
        self.debug_mode = False
        self.verbose_mode = False
        self.rate_limit_delay = RATE_LIMIT_DELAY
        self.dns_servers = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222']
        self.output_dir = 'results'
        self.proxies = None
        
    def _setup_infrastructure(self):
        """Set up connections and sessions"""
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        
        # Configure adapters for connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
    def load_config(self) -> None:
        """Load configuration from file or set defaults"""
        config = configparser.ConfigParser()
        
        # Default configuration
        config['DEFAULT'] = {
            'debug_mode': 'False',
            'verbose_mode': 'False',
            'rate_limit_delay': str(RATE_LIMIT_DELAY),
            'dns_servers': ','.join(self.dns_servers),
            'output_dir': self.output_dir,
            'proxies': ''
        }
        
        # Try to read or create config file
        try:
            if os.path.exists(self.config_file):
                config.read(self.config_file)
            else:
                with open(self.config_file, 'w') as configfile:
                    config.write(configfile)
                print(Fore.YELLOW + f"[*] Created default config file: {self.config_file}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error loading config: {e}" + Style.RESET_ALL)
            return

        # Apply configuration
        try:
            self.debug_mode = config.getboolean('DEFAULT', 'debug_mode', fallback=False)
            self.verbose_mode = config.getboolean('DEFAULT', 'verbose_mode', fallback=False)
            self.rate_limit_delay = config.getfloat('DEFAULT', 'rate_limit_delay', fallback=RATE_LIMIT_DELAY)
            self.dns_servers = [s.strip() for s in config.get('DEFAULT', 'dns_servers').split(',')]
            self.output_dir = config.get('DEFAULT', 'output_dir', fallback='results')
            proxy_str = config.get('DEFAULT', 'proxies', fallback='')
            if proxy_str:
                self.configure_proxy(proxy_str)
            
            # Create output directory if it doesn't exist
            os.makedirs(self.output_dir, exist_ok=True)
            
            # Load ranges from files if they exist (overriding config)
            for cdn in self.cdn_ranges:
                filename = f"{cdn}.txt"
                if os.path.exists(filename):
                    try:
                        with open(filename, 'r') as f:
                            self.cdn_ranges[cdn] = [line.strip() for line in f if line.strip()]
                    except Exception as e:
                        print(Fore.RED + f"[!] Error loading {cdn} ranges: {e}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error applying config: {e}" + Style.RESET_ALL)


    def scan_cloudflare_multiport(self) -> None:
        """Enhanced Scanner to find Clean IPs for Xray/VLESS Nodes"""
        self.print_banner()
        print(Fore.GREEN + "--- Multi-Port CDN Scanner (GFW Bypass Mode) ---" + Style.RESET_ALL)
        
        # 1. FILE DETECTION
        files_to_check = {
            "1": ("valid_pairs.json", "Option 2: Random Scan Results"),
            "2": ("xray_working.json", "Option 9: Xray-Tested Results")
        }
        
        available_files = {k: v for k, v in files_to_check.items() if os.path.exists(os.path.join(self.output_dir, v[0]))}
        
        test_ips = []
        source_name = ""

        # 2. USER CHOICE MENU
        print(Fore.CYAN + "\n[?] Select source for Clean IPs:")
        if available_files:
            for key, (fname, desc) in available_files.items():
                print(f"{Fore.YELLOW}[{key}]{Style.RESET_ALL} {desc} ({fname})")
        else:
            print(Fore.RED + " [!] No result files found. You should run a scan first." + Style.RESET_ALL)
            
        print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} Scan new random Cloudflare ranges (Fallback)")
        
        choice = input(Fore.WHITE + "\nEnter choice (1-3): " + Style.RESET_ALL).strip()

        # 3. ROBUST PARSING (Handles standard JSON and Xray List format)
        if choice in available_files:
            selected_filename = available_files[choice][0]
            target_path = os.path.join(self.output_dir, selected_filename)
            source_name = selected_filename
            
            try:
                with open(target_path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        try:
                            # Try loading as [ {...}, {...} ]
                            data = json.loads(content)
                            entries = data if isinstance(data, list) else [data]
                            for entry in entries:
                                ip = entry.get('ip') or entry.get('host')
                                if ip: test_ips.append(ip)
                        except json.JSONDecodeError:
                            # Fallback to line-by-line { "ip": ... }
                            f.seek(0)
                            for line in f:
                                line = line.strip().rstrip(',')
                                if not line or line in ['[', ']']: continue
                                try:
                                    entry = json.loads(line)
                                    ip = entry.get('ip') or entry.get('host')
                                    if ip: test_ips.append(ip)
                                except: continue
                test_ips = list(set(test_ips)) # De-duplicate
            except Exception as e:
                print(Fore.RED + f"[✘] Error loading source: {e}")

        # Fallback to random generation if choice 3 or loading failed
        if choice == '3' or not test_ips:
            source_name = "Cloudflare Random Ranges"
            if hasattr(self, 'cdn_ranges') and 'cloudflare' in self.cdn_ranges:
                cidr = random.choice(self.cdn_ranges['cloudflare'])
                test_ips = self.generate_random_ips(cidr, 50)
            else:
                print(Fore.RED + "[!] Critical: No IP ranges found.")
                return

        # 4. STATUS BOX
        print(Fore.CYAN + "\n┌────────────────────────────────────────────────────────────┐")
        print(f"│ {Fore.GREEN}SOURCE:{Style.RESET_ALL} {source_name:<19} | {Fore.GREEN}IPs LOADED:{Style.RESET_ALL} {len(test_ips):<6} │")
        print(Fore.CYAN + "└────────────────────────────────────────────────────────────┘" + Style.RESET_ALL)

        # 5. SNI SELECTION (Commonly unblocked SNIs in Iran)
        print(Fore.CYAN + "\n--- Select SNI for Scanning ---")
        print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} Cloudflare (www.speedtest.net) - High Success")
        print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} GCore (gcore.com)")
        print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} Fastly (fastly.com)")
        print(f"{Fore.YELLOW}[4]{Style.RESET_ALL} Fastly (fastly.net)")
        print(f"{Fore.YELLOW}[5]{Style.RESET_ALL} Custom SNI")
        
        sni_choice = input(Fore.YELLOW + "Choice (1-5): " + Style.RESET_ALL).strip()
        sni_map = {"1": "www.speedtest.net", "2": "gcore.com", "3": "fastly.com", "4": "fastly.net"}
        sni = sni_map.get(sni_choice) or input(Fore.YELLOW + "Enter Custom SNI: " + Style.RESET_ALL).strip() or "www.speedtest.net"

        # 6. PORT SELECTION
        port_input = input(Fore.YELLOW + "\nEnter ports (e.g. 443,2053,2083) or 'all': " + Style.RESET_ALL).strip().lower()
        selected_ports = [443, 2053, 2083, 2087, 2096, 8443] if port_input in ['all', ''] else [int(p.strip()) for p in port_input.split(',')]

        # 7. EXECUTION
        print(Fore.CYAN + f"\n[*] Scanning {len(test_ips)} IPs for {sni} compatibility...")
        txt_file = os.path.join(self.output_dir, "multiport_results.txt")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.test_sni_pair, ip, sni, 10, port): (ip, port) for ip in test_ips for port in selected_ports}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result.get('https_works'):
                    ip, port, ping = result['ip'], result['port'], result['ping']
                    print(Fore.GREEN + f" [+] CLEAN IP FOUND: {ip}:{port} | Ping: {ping}ms" + Style.RESET_ALL)
                    
                    with open(txt_file, 'a') as f:
                        f.write(f"{ip}:{port} | SNI: {sni} | Ping: {ping}ms\n")

        print(Fore.YELLOW + f"\n[*] Done! Use these IPs in your VLESS nodes. Results: multiport_results.txt")
        input("\nPress Enter to return...")
        
    def configure_proxy(self, proxy_url: str):
        """Configure HTTP/S proxy"""
        self.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        self.session.proxies = self.proxies
        logging.info(f"Proxy configured: {proxy_url}")

    def setup_logging(self) -> None:
        """Configure logging system"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        level = logging.DEBUG if self.debug_mode else logging.INFO
        
        logging.basicConfig(
            level=level,
            format=log_format,
            filename=os.path.join(self.output_dir, 'cdn_scanner.log'),
            filemode='a'
        )

    def clear_screen(self) -> None:
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self) -> None:
        """Display the program banner"""
        self.clear_screen()
        print(Fore.CYAN + r"""
   ____ ____  _   _   ____ ___ ____ _   _ _____ 
  / ___|  _ \| \ | | / ___|_ _/ ___| \ | |_   _|
 | |   | | | |  \| | \___ \| | |  _|  \| | | |  
 | |___| |_| | |\  |  ___) | | |_| | |\  | | |  
  \____|____/|_| \_| |____/___\____|_| \_| |_|  
        CDN SNI Scanner PLUS - IRAN OPTIMIZED By Jeet
        """ + Style.RESET_ALL)
        print(Fore.YELLOW + "VLESS+WS/Xray Support | GFW Bypass | Enhanced Reporting" + Style.RESET_ALL)

    def print_menu(self) -> None:
        """Display the main menu"""
        self.print_banner()
        debug_status = f"{Fore.GREEN}●{Style.RESET_ALL}" if self.debug_mode else f"{Fore.RED}○{Style.RESET_ALL}"
        verbose_status = f"{Fore.GREEN}●{Style.RESET_ALL}" if self.verbose_mode else f"{Fore.RED}○{Style.RESET_ALL}"
        
        print(f"{debug_status} Debug Mode | {verbose_status} Verbose Mode | Proxies: {'Enabled' if self.proxies else 'Disabled'}\n")
        
        print(Fore.YELLOW + "[1]" + Style.RESET_ALL + " Scan single domain")
        print(Fore.YELLOW + "[2]" + Style.RESET_ALL + " Scan random IPs")
        print(Fore.YELLOW + "[3]" + Style.RESET_ALL + " Scan from file")
        print(Fore.YELLOW + "[4]" + Style.RESET_ALL + " View results")
        print(Fore.YELLOW + "[5]" + Style.RESET_ALL + " Toggle debug")
        print(Fore.YELLOW + "[6]" + Style.RESET_ALL + " Test known CDNs")
        print(Fore.YELLOW + "[7]" + Style.RESET_ALL + " Deep CDN Test")
        print(Fore.CYAN + "[8]" + Style.RESET_ALL + " Update CDN IP ranges")
        print(Fore.GREEN + "[9]" + Style.RESET_ALL + " Test Xray/V2Ray compatibility")
        print(Fore.WHITE  + "[10]" + Style.RESET_ALL + " CDN Multi-Port Scanner")
        print(Fore.GREEN + "[11]" + Style.RESET_ALL + " Generate HTML report")
        print(Fore.YELLOW + "[12]" + Style.RESET_ALL + " Configuration")
        print(Fore.YELLOW + "[13]" + Style.RESET_ALL + " Export to CSV/Excel")
        print(Fore.RED + "[0]" + Style.RESET_ALL + " Exit")
        print("\n")

    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        ips = set()
        record_types = ['A', 'AAAA']  # Both IPv4 and IPv6
        
        for dns_server in self.dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                
                for record_type in record_types:
                    try:
                        answers = resolver.resolve(domain, record_type)
                        ips.update(str(r) for r in answers)
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        continue
                    
                if ips:
                    break
            except Exception as e:
                logging.warning(f"DNS resolution failed with {dns_server} for {domain}: {e}")
                if self.debug_mode:
                    print(Fore.RED + f"[DEBUG] DNS resolution failed with {dns_server} for {domain}: {type(e).__name__}" + Style.RESET_ALL)
        
        return list(ips)

    def is_ip_in_cdn_ranges(self, ip: str, cdn_name: str) -> bool:
        """Check if IP belongs to CDN ranges"""
        try:
            ip_obj = ip_address(ip)
            for network in self.cdn_ranges.get(cdn_name.lower(), []):
                try:
                    if ip_obj.version == 4:
                        if ip_obj in IPv4Network(network):
                            return True
                    elif ip_obj.version == 6:
                        if ip_obj in IPv6Network(network):
                            return True
                except ValueError:
                    continue
            return False
        except ValueError:
            logging.warning(f"Invalid IP address: {ip}")
            if self.debug_mode:
                print(Fore.RED + f"[DEBUG] Invalid IP address: {ip}" + Style.RESET_ALL)
            return False

    def get_ping(self, ip: str, count: int = 3) -> Optional[float]:
        """
        Get average ping time to an IP address
        Returns average ping in milliseconds or None if failed
        """
        try:
            # Ping command differs between Windows and Unix-like systems
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, str(count), ip]
            
            output = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            ).stdout
            
            # Parse ping output for average time
            if platform.system().lower() == 'windows':
                match = re.search(r'Average = (\d+)ms', output)
            else:
                match = re.search(r'min/avg/max/\w+ = [\d.]+/([\d.]+)/', output)
            
            if match:
                return float(match.group(1))
            return None
        except:
            return None

    def test_http(self, ip: str, hostname: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
        """Test if IP responds to HTTP (port 80) with given Host header"""
        try:
            # Create a socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, 80))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            
            # Get response (just the first part is enough)
            response = sock.recv(1024).decode()
            
            # Check if we got a valid HTTP response
            if "HTTP/" in response and any(str(code) in response for code in [200, 301, 302, 403, 404]):
                return True
        except:
            return False
        finally:
            try:
                sock.close()
            except:
                pass
        return False

    def test_sni_pair(self, ip: str, sni: str, timeout: int = DEFAULT_TIMEOUT, port: int = 443) -> Optional[Dict]:
        """Test if IP accepts the SNI with detailed performance metrics"""
        for attempt in range(MAX_RETRIES):
            try:
                # FIXED: Added 'port' here so it actually passes it to the worker function
                return self._test_sni_pair(ip, sni, timeout, port)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    if self.debug_mode:
                        print(Fore.YELLOW + f"[DEBUG] Test failed for {sni} @ {ip}:{port}: {e}" + Style.RESET_ALL)
                    return None
                time.sleep(random.uniform(0.5, 1.5))
        return None

    def _test_sni_pair(self, ip: str, sni: str, timeout: int, port: int) -> Optional[Dict]:
        """Actual implementation of SNI testing"""
        self.total_tests += 1
        time.sleep(self.rate_limit_delay)
        
        result = {
            'ip': ip,
            'sni': sni,
            'https_works': False,
            'http_works': False,
            'ping': None,
            'ssl_handshake_time': None,
            'http_response_time': None,
            'reverse_dns': self.reverse_dns_lookup(ip),
            'server_header': None,
            'port': port # Correctly capture the port used
        }
        
        # Test HTTPS
        ssl_success = False
        try:
            # FIXED: Ensure socket is created using the passed port
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.settimeout(timeout)
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            start_time = timer()
            with context.wrap_socket(sock, server_hostname=sni) as ssl_sock:
                # If handshake finishes, we consider it a success for that port
                result['ssl_handshake_time'] = (timer() - start_time) * 1000
                
                try:
                    request = f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                    ssl_sock.sendall(request.encode())
                    response = ssl_sock.recv(1024).decode(errors='ignore')
                    
                    if "HTTP/" in response:
                        result['https_works'] = True
                        ssl_success = True
                        if 'Server:' in response:
                            result['server_header'] = response.split('Server:')[1].split('\r\n')[0].strip()
                except:
                    # Even if request fails, if SSL handshake worked, the port is open
                    result['https_works'] = True
                    ssl_success = True
                    
        except Exception as e:
            if self.debug_mode:
                print(Fore.RED + f"[-] {ip}:{port} failed: {e}" + Style.RESET_ALL)
        
        # Only ping if the connection was successful
        if ssl_success:
            ping_time = self.get_ping(ip)
            result['ping'] = ping_time
            return result
        return None

    def test_sni_pair(self, ip: str, sni: str, timeout: int = DEFAULT_TIMEOUT, port: int = 443) -> Optional[Dict]:
        """Test if IP accepts the SNI with detailed performance metrics"""
        for attempt in range(MAX_RETRIES):
            try:
                # FIXED: Added 'port' here so it actually passes it to the worker function
                return self._test_sni_pair(ip, sni, timeout, port)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    if self.debug_mode:
                        print(Fore.YELLOW + f"[DEBUG] Test failed for {sni} @ {ip}:{port}: {e}" + Style.RESET_ALL)
                    return None
                time.sleep(random.uniform(0.5, 1.5))
        return None

    def _test_sni_pair(self, ip: str, sni: str, timeout: int, port: int) -> Optional[Dict]:
        """Actual implementation of SNI testing"""
        self.total_tests += 1
        time.sleep(self.rate_limit_delay)
        
        result = {
            'ip': ip,
            'sni': sni,
            'https_works': False,
            'http_works': False,
            'ping': None,
            'ssl_handshake_time': None,
            'http_response_time': None,
            'reverse_dns': self.reverse_dns_lookup(ip),
            'server_header': None,
            'port': port # Correctly capture the port used
        }
        
        # Test HTTPS
        ssl_success = False
        try:
            # FIXED: Ensure socket is created using the passed port
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.settimeout(timeout)
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            start_time = timer()
            with context.wrap_socket(sock, server_hostname=sni) as ssl_sock:
                # If handshake finishes, we consider it a success for that port
                result['ssl_handshake_time'] = (timer() - start_time) * 1000
                
                try:
                    request = f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                    ssl_sock.sendall(request.encode())
                    response = ssl_sock.recv(1024).decode(errors='ignore')
                    
                    if "HTTP/" in response:
                        result['https_works'] = True
                        ssl_success = True
                        if 'Server:' in response:
                            result['server_header'] = response.split('Server:')[1].split('\r\n')[0].strip()
                except:
                    # Even if request fails, if SSL handshake worked, the port is open
                    result['https_works'] = True
                    ssl_success = True
                    
        except Exception as e:
            if self.debug_mode:
                print(Fore.RED + f"[-] {ip}:{port} failed: {e}" + Style.RESET_ALL)
        
        # Only ping if the connection was successful
        if ssl_success:
            ping_time = self.get_ping(ip)
            result['ping'] = ping_time
            return result
        return None

    def reverse_dns_lookup(self, ip: str) -> List[str]:
        """Perform a reverse DNS lookup (PTR record) to find domains linked to an IP."""
        try:
            hostnames = socket.gethostbyaddr(ip)
            return [hostnames[0]] + hostnames[1]  # Primary + aliases
        except (socket.herror, socket.gaierror):
            return []
        except Exception as e:
            if self.debug_mode:
                print(Fore.YELLOW + f"[DEBUG] Reverse DNS failed for {ip}: {e}" + Style.RESET_ALL)
            return []

    def scan_domain(self, domain: str, output_file: Optional[str] = None) -> List[Dict]:
        """Scan a single domain for CDN IPs"""
        self.scanned_domains += 1
        print(Fore.GREEN + f"\n[*] Scanning {domain}" + Style.RESET_ALL)
        
        ips = self.resolve_domain(domain)
        if not ips:
            print(Fore.YELLOW + f"[!] No IPs found for {domain}" + Style.RESET_ALL)
            return []

        valid_pairs = []
        
        for cdn_name in self.cdn_ranges:
            cdn_ips = [ip for ip in ips if self.is_ip_in_cdn_ranges(ip, cdn_name)]
            if not cdn_ips:
                if self.debug_mode:
                    print(Fore.CYAN + f"[DEBUG] No {cdn_name} IPs found for {domain}" + Style.RESET_ALL)
                continue
            
            print(Fore.CYAN + f"[*] Found {len(cdn_ips)} {cdn_name} IPs" + Style.RESET_ALL)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(self.test_sni_pair, ip, domain): (ip, domain, cdn_name) for ip in cdn_ips}
                
                for future in concurrent.futures.as_completed(futures):
                    ip, domain, cdn_name = futures[future]
                    try:
                        result = future.result()
                        if result:
                            pair = {
                                "ip": ip,
                                "sni": domain,
                                "cdn": cdn_name,
                                "https_works": result.get('https_works', False),
                                "http_works": result.get('http_works', False),
                                "ping": result.get('ping', None),
                                "ssl_handshake_time": result.get('ssl_handshake_time', None),
                                "http_response_time": result.get('http_response_time', None),
                                "reverse_dns": result.get('reverse_dns', []),
                                "server_header": result.get('server_header', None),
                                "timestamp": datetime.now().isoformat()
                            }
                            
                            # Build status message
                            status_parts = []
                            if pair['https_works']:
                                status_parts.append("HTTPS")
                            if pair['http_works']:
                                status_parts.append("HTTP")
                            status = "+".join(status_parts) if status_parts else "None"
                            
                            ping_display = f"{pair['ping']}ms" if pair['ping'] is not None else "N/A"
                            ssl_time_display = f"{pair['ssl_handshake_time']:.1f}ms" if pair['ssl_handshake_time'] is not None else "N/A"
                            http_time_display = f"{pair['http_response_time']:.1f}ms" if pair['http_response_time'] is not None else "N/A"
                            reverse_dns_display = ", ".join(pair['reverse_dns']) if pair['reverse_dns'] else "None"
                            server_header_display = pair['server_header'] or "N/A"
                            
                            print(Fore.GREEN + f"[+] Valid: {domain} @ {ip} ({cdn_name}) - Protocols: {status} - Ping: {ping_display}" + Style.RESET_ALL)
                            print(Fore.CYAN + f"    SSL Handshake: {ssl_time_display} - HTTP Response: {http_time_display}" + Style.RESET_ALL)
                            print(Fore.CYAN + f"    Server: {server_header_display}" + Style.RESET_ALL)
                            print(Fore.CYAN + f"    Reverse DNS: {reverse_dns_display}" + Style.RESET_ALL)
                            
                            valid_pairs.append(pair)
                            if output_file:
                                self.save_result(pair, output_file)
                    except Exception as e:
                        print(Fore.RED + f"[!] Error testing {domain} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)
        return valid_pairs

    def save_result(self, pair: Dict, output_file: str) -> None:
        """Save a valid pair to output file"""
        try:
            with open(output_file, 'a') as f:
                f.write(json.dumps(pair) + "\n")
        except IOError as e:
            print(Fore.RED + f"[!] Failed to save results: {e}" + Style.RESET_ALL)

    def save_to_txt(self, results: List[Dict], filename: str) -> None:
        """Save results to TXT file with ping info"""
        try:
            # Sort by ping time (lowest first)
            sorted_results = sorted(
                results,
                key=lambda x: float('inf') if x.get('ping') is None else x['ping']
            )
            
            with open(filename, 'w') as f:
                for result in sorted_results:
                    f.write(f"IP: {result.get('ip', 'N/A')}\n")
                    f.write(f"SNI: {result.get('sni', 'N/A')}\n")
                    f.write(f"CDN: {result.get('cdn', 'N/A')}\n")
                    f.write(f"HTTPS Works: {'Yes' if result.get('https_works', False) else 'No'}\n")
                    f.write(f"HTTP Works: {'Yes' if result.get('http_works', False) else 'No'}\n")
                    f.write(f"Server Header: {result.get('server_header', 'N/A')}\n")
                    f.write(f"Reverse DNS: {', '.join(result.get('reverse_dns', [])) or 'None'}\n")
                    f.write(f"Ping: {result.get('ping', 'N/A')}ms\n")
                    f.write(f"SSL Handshake Time: {result.get('ssl_handshake_time', 'N/A')}ms\n")
                    f.write(f"HTTP Response Time: {result.get('http_response_time', 'N/A')}ms\n")
                    f.write("-" * 40 + "\n")
        except Exception as e:
            print(Fore.RED + f"[!] Error saving TXT file: {e}" + Style.RESET_ALL)

    def view_results(self, results_file: Optional[str] = None) -> None:
        """Display saved results"""
        self.print_banner()
        if not results_file:
            results_file = os.path.join(self.output_dir, "valid_pairs.json")
        
        if not os.path.exists(results_file):
            print(Fore.RED + "[!] No results file found" + Style.RESET_ALL)
            input("\nPress Enter to return to menu...")
            return

        try:
            with open(results_file, 'r') as f:
                results = [json.loads(line) for line in f if line.strip()]
            
            if not results:
                print(Fore.YELLOW + "[!] No valid pairs found in results file" + Style.RESET_ALL)
            else:
                print(Fore.CYAN + "\nSaved Valid SNI + IP Pairs:\n" + Style.RESET_ALL)
                for i, pair in enumerate(results, 1):
                    protocols = []
                    if pair.get('https_works', False):
                        protocols.append("HTTPS")
                    if pair.get('http_works', False):
                        protocols.append("HTTP")
                    protocol_str = "+".join(protocols) if protocols else "None"
                    
                    ping_display = f"{pair.get('ping', 'N/A')}ms"
                    ssl_time = f"{pair.get('ssl_handshake_time', 'N/A')}ms"
                    http_time = f"{pair.get('http_response_time', 'N/A')}ms"
                    reverse_dns = ", ".join(pair.get('reverse_dns', [])) or "None"
                    server_header = pair.get('server_header', 'N/A')
                    
                    print(f"{i}. {pair.get('sni', 'N/A')} @ {pair.get('ip', 'N/A')} ({pair.get('cdn', 'N/A')})")
                    print(f"   Protocols: {protocol_str} - Ping: {ping_display}")
                    print(f"   SSL Time: {ssl_time} - HTTP Time: {http_time}")
                    print(f"   Server: {server_header}")
                    print(f"   Reverse DNS: {reverse_dns}")
                    if 'xray_works' in pair:
                        xray_status = Fore.GREEN + "WORKING" if pair['xray_works'] else Fore.RED + "FAILED"
                        print(f"   Xray Status: {xray_status}{Style.RESET_ALL}")
                    print()
                
                print(Fore.GREEN + f"\nTotal valid pairs: {len(results)}" + Style.RESET_ALL)
                
                # Offer to save as TXT
                if input("\nSave as TXT file? (y/n): ").lower() == 'y':
                    txt_file = results_file.replace('.json', '.txt')
                    self.save_to_txt(results, txt_file)
        except Exception as e:
            print(Fore.RED + f"[!] Error reading results: {e}" + Style.RESET_ALL)
        
        input("\nPress Enter to return to menu...")

    def scan_random_ips(self) -> None:
        """Scan random IPs from CDN ranges"""
        self.print_banner()
        print(Fore.CYAN + "Random IP Scanner\n" + Style.RESET_ALL)
        
        # Let user select CDN
        print("Select CDN to scan:")
        for i, cdn in enumerate(self.cdn_ranges.keys(), 1):
            print(f"{i}. {cdn} ({len(self.cdn_ranges[cdn])} ranges)")
        
        try:
            choice = int(input("Enter choice (1-3): ")) - 1
            cdn_name = list(self.cdn_ranges.keys())[choice]
        except:
            print(Fore.RED + "[!] Invalid choice" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        # Get number of IPs to test
        try:
            ip_count = int(input("How many random IPs to test? (10-1000): "))
            ip_count = max(10, min(1000, ip_count))
        except:
            ip_count = 100
        
        # Get SNI hostname
        sni = input("Enter SNI hostname to test (e.g., gcore.com,www.speedtest.net for cloudflare,fastly.net or com ): ").strip()
        if not sni:
            print(Fore.RED + "[!] SNI hostname required" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_file = os.path.join(self.output_dir, "valid_pairs.json")
        
        print(Fore.YELLOW + f"\n[*] Generating {ip_count} random IPs from {cdn_name} ranges..." + Style.RESET_ALL)
        
        # Generate random IPs from all ranges
        all_ips = []
        for cidr in self.cdn_ranges[cdn_name]:
            try:
                ips = self.generate_random_ips(cidr, max(1, ip_count // len(self.cdn_ranges[cdn_name])))
                all_ips.extend(ips)
            except:
                continue
        
        # Shuffle and limit to requested count
        random.shuffle(all_ips)
        test_ips = all_ips[:ip_count]
        
        print(Fore.YELLOW + f"[*] Starting scan of {len(test_ips)} IPs..." + Style.RESET_ALL)
        self.start_time = time.time()
        
        valid_pairs = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self.test_sni_pair, ip, sni, DEFAULT_TIMEOUT, port=443 ): ip for ip in test_ips}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        pair = {
                            "ip": ip,
                            "sni": sni,
                            "cdn": cdn_name,
                            "https_works": result.get('https_works', False),
                            "http_works": result.get('http_works', False),
                            "ping": result.get('ping', None),
                            "ssl_handshake_time": result.get('ssl_handshake_time', None),
                            "http_response_time": result.get('http_response_time', None),
                            "reverse_dns": result.get('reverse_dns', []),
                            "server_header": result.get('server_header', None),
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        # Build status message
                        status_parts = []
                        if pair['https_works']:
                            status_parts.append("HTTPS")
                        if pair['http_works']:
                            status_parts.append("HTTP")
                        status = "+".join(status_parts) if status_parts else "None"
                        
                        ping_display = f"{pair['ping']}ms" if pair['ping'] is not None else "N/A"
                        ssl_time_display = f"{pair['ssl_handshake_time']:.1f}ms" if pair['ssl_handshake_time'] is not None else "N/A"
                        http_time_display = f"{pair['http_response_time']:.1f}ms" if pair['http_response_time'] is not None else "N/A"
                        reverse_dns_display = ", ".join(pair['reverse_dns']) if pair['reverse_dns'] else "None"
                        server_header_display = pair['server_header'] or "N/A"
                        
                        print(Fore.GREEN + f"[+] Valid pair found: {sni} @ {ip} ({cdn_name}) - Protocols: {status} - Ping: {ping_display}" + Style.RESET_ALL)
                        print(Fore.CYAN + f"    SSL Handshake: {ssl_time_display} - HTTP Response: {http_time_display}" + Style.RESET_ALL)
                        print(Fore.CYAN + f"    Server: {server_header_display}" + Style.RESET_ALL)
                        print(Fore.CYAN + f"    Reverse DNS: {reverse_dns_display}" + Style.RESET_ALL)
                        
                        valid_pairs.append(pair)
                        
                        if output_file:
                            self.save_result(pair, output_file)
                except Exception as e:
                    print(Fore.RED + f"[!] Error testing {sni} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)
                
                # Progress update
                if i % 10 == 0 or i == len(test_ips):
                    elapsed = time.time() - self.start_time
                    print(Fore.CYAN + f"[*] Progress: {i}/{len(test_ips)} IPs tested | Found: {len(valid_pairs)} | Elapsed: {elapsed:.1f}s" + Style.RESET_ALL)
        
        elapsed = time.time() - self.start_time
        print(Fore.GREEN + f"\n[+] Scan completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        print(Fore.CYAN + f"Valid pairs found: {len(valid_pairs)}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Results saved to {output_file}" + Style.RESET_ALL)
        input("\nPress Enter to return to menu...")

    def generate_random_ips(self, cidr: str, count: int) -> List[str]:
        """Generate random IPs from a CIDR range"""
        try:
            network = IPv4Network(cidr)
            return [str(network[random.randint(0, network.num_addresses - 1)]) for _ in range(count)]
        except ValueError:
            try:
                network = IPv6Network(cidr)
                return [str(network[random.randint(0, network.num_addresses - 1)]) for _ in range(count)]
            except ValueError:
                return []

    def run_file_scan(self) -> None:
        """Scan domains from a file"""
        self.print_banner()
        print(Fore.CYAN + "Batch Domain Scan\n" + Style.RESET_ALL)
        input_file = input("Enter path to domains file: ").strip()
        
        if not input_file:
            print(Fore.RED + "[!] No file specified" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_file = os.path.join(self.output_dir, "valid_pairs.json")
        
        domains = self.load_domains_from_file(input_file)
        if not domains:
            time.sleep(2)
            return
        
        print(Fore.YELLOW + f"\n[*] Found {len(domains)} domains to scan" + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] Starting scan..." + Style.RESET_ALL)
        self.start_time = time.time()
        
        all_valid_pairs = []
        for domain in domains:
            valid_pairs = self.scan_domain(domain, output_file)
            all_valid_pairs.extend(valid_pairs)
        
        elapsed = time.time() - self.start_time
        print(Fore.GREEN + f"\n[+] Scan completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        print(Fore.CYAN + f"Total valid pairs found: {len(all_valid_pairs)}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Results saved to {output_file}" + Style.RESET_ALL)
        input("\nPress Enter to return to menu...")

    def load_domains_from_file(self, file_path: str) -> List[str]:
        """Load domains from a text file"""
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(Fore.RED + f"[!] File not found: {file_path}" + Style.RESET_ALL)
            return []
        except Exception as e:
            print(Fore.RED + f"[!] Error reading file: {e}" + Style.RESET_ALL)
            return []

    def test_known_cdns(self) -> None:
        """Test with known CDN domains"""
        print(Fore.CYAN + "\n[*] Testing with known CDN domains..." + Style.RESET_ALL)
        self.start_time = time.time()
        
        all_results = []
        for cdn_name, domains in self.cdn_test_domains.items():
            for domain in domains:
                print(Fore.YELLOW + f"\n[*] Testing {domain} (expected: {cdn_name})" + Style.RESET_ALL)
                valid_pairs = self.scan_domain(domain)
                
                if valid_pairs:
                    print(Fore.GREEN + f"[+] Found {len(valid_pairs)} valid pairs for {domain}" + Style.RESET_ALL)
                    for pair in valid_pairs:
                        protocols = []
                        if pair.get('https_works', False):
                            protocols.append("HTTPS")
                        if pair.get('http_works', False):
                            protocols.append("HTTP")
                        protocol_str = "+".join(protocols) if protocols else "None"
                        
                        ping_display = f"{pair.get('ping', 'N/A')}ms"
                        ssl_time = f"{pair.get('ssl_handshake_time', 'N/A')}ms"
                        http_time = f"{pair.get('http_response_time', 'N/A')}ms"
                        reverse_dns = ", ".join(pair.get('reverse_dns', [])) or "None"
                        server_header = pair.get('server_header', 'N/A')
                        
                        print(f"  - {pair.get('ip', 'N/A')} ({pair.get('cdn', 'N/A')})")
                        print(f"     Protocols: {protocol_str} - Ping: {ping_display}")
                        print(f"     SSL Time: {ssl_time} - HTTP Time: {http_time}")
                        print(f"     Server: {server_header}")
                        print(f"     Reverse DNS: {reverse_dns}")
                        print()
                    all_results.extend(valid_pairs)
                else:
                    print(Fore.RED + f"[!] No valid pairs found for {domain}" + Style.RESET_ALL)
        
        # Save results
        if all_results:
            output_json = os.path.join(self.output_dir, "known_cdn_results.json")
            
            with open(output_json, 'w') as f:
                json.dump(all_results, f, indent=2)
            
            print(Fore.GREEN + f"\n[+] JSON results saved to {output_json}" + Style.RESET_ALL)
        
        elapsed = time.time() - self.start_time
        print(Fore.CYAN + f"\n[*] Test completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        input("\nPress Enter to return to menu...")

    def test_specific_cdn(self) -> None:
        """Test specific CDN with its known domains"""
        self.print_banner()
        print(Fore.CYAN + "Deep CDN Test\n" + Style.RESET_ALL)
        
        print("Select CDN for deep testing:")
        for i, cdn in enumerate(self.cdn_test_domains.keys(), 1):
            print(f"{i}. {cdn}")
        
        try:
            choice = int(input("Enter choice (1-3): ")) - 1
            cdn_name = list(self.cdn_test_domains.keys())[choice]
            test_domains = self.cdn_test_domains[cdn_name]
        except:
            print(Fore.RED + "[!] Invalid choice" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_json = os.path.join(self.output_dir, f"{cdn_name}_results.json")
        
        all_results = []
        for domain in test_domains:
            print(Fore.YELLOW + f"\n[*] Testing: {domain}" + Style.RESET_ALL)
            ips = self.resolve_domain(domain)
            print(Fore.CYAN + f"[*] Resolved IPs: {ips}" + Style.RESET_ALL)
            
            for ip in ips:
                result = self.test_sni_pair(ip, domain)
                if result:
                    pair = {
                        "ip": ip,
                        "sni": domain,
                        "cdn": cdn_name,
                        "https_works": result.get('https_works', False),
                        "http_works": result.get('http_works', False),
                        "ping": result.get('ping', None),
                        "ssl_handshake_time": result.get('ssl_handshake_time', None),
                        "http_response_time": result.get('http_response_time', None),
                        "reverse_dns": result.get('reverse_dns', []),
                        "server_header": result.get('server_header', None),
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    protocols = []
                    if result['https_works']:
                        protocols.append("HTTPS")
                    if result['http_works']:
                        protocols.append("HTTP")
                    protocol_str = "+".join(protocols) if protocols else "None"
                    
                    ping_display = f"{result['ping']}ms" if result['ping'] is not None else "N/A"
                    ssl_time = f"{result['ssl_handshake_time']:.1f}ms" if result['ssl_handshake_time'] is not None else "N/A"
                    http_time = f"{result['http_response_time']:.1f}ms" if result['http_response_time'] is not None else "N/A"
                    reverse_dns = ", ".join(result['reverse_dns']) if result['reverse_dns'] else "None"
                    server_header = result['server_header'] or "N/A"
                    
                    print(Fore.GREEN + f"[+] Valid {cdn_name}: {domain} @ {ip}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Protocols: {protocol_str} - Ping: {ping_display}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    SSL Time: {ssl_time} - HTTP Time: {http_time}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Server: {server_header}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Reverse DNS: {reverse_dns}" + Style.RESET_ALL)
                    
                    all_results.append(pair)
                else:
                    print(Fore.RED + f"[-] Failed: {domain} @ {ip}" + Style.RESET_ALL)
        
        # Save results
        if all_results:
            with open(output_json, 'w') as f:
                json.dump(all_results, f, indent=2)
            
            print(Fore.GREEN + f"\n[+] JSON results saved to {output_json}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "\n[!] No valid pairs found" + Style.RESET_ALL)
        
        input("\nPress Enter to return to menu...")

    def update_cdn_ranges(self) -> None:
        """Automatically update CDN IP ranges from online sources with fallbacks"""
        cdn_sources = {
            'cloudflare': {
                'url': 'https://www.cloudflare.com/ips-v4',
                'fallback': self.cdn_ranges.get('cloudflare', [])
            },
            'gcore': {
                'url': 'https://api.gcore.com/cdn/public-ip-list',
                'fallback': [
                    '158.160.0.0/16', '92.223.84.0/24', '185.209.160.0/24',
                    '45.133.144.0/24', '45.135.240.0/22', '45.159.216.0/22'
                ],
                'alternative_url': 'https://cdn.gcorelabs.com/ip-list.txt'
            },
            'fastly': {
                'url': 'https://api.fastly.com/public-ip-list',
                'fallback': [
                    '151.101.0.0/16', '199.232.0.0/16', '2a04:4e40::/32',
                    '23.235.32.0/20', '43.249.72.0/22'
                ],
                'alternative_url': 'https://ip-ranges.fastly.com/'
            }
        }
        
        print(Fore.YELLOW + "\n[*] Updating CDN IP ranges...USE VPN IF UR INTERNET IS FUCKED UP for this part" + Style.RESET_ALL)
        
        for cdn, sources in cdn_sources.items():
            ranges = []
            success = False
            
            # Try primary URL first
            try:
                print(Fore.CYAN + f"[*] Trying to fetch {cdn} ranges from primary source..." + Style.RESET_ALL)
                response = self.session.get(sources['url'], timeout=15)
                response.raise_for_status()
                
                if cdn == 'cloudflare':
                    ranges = [line.strip() for line in response.text.split('\n') if line.strip()]
                elif cdn == 'gcore':
                    data = response.json()
                    ranges = data.get('addresses', []) + data.get('prefixes', [])
                elif cdn == 'fastly':
                    data = response.json()
                    ranges = data.get('addresses', [])
                
                success = True
                print(Fore.GREEN + f"[+] Successfully updated {cdn} ranges from primary source" + Style.RESET_ALL)
                
            except Exception as e:
                print(Fore.YELLOW + f"[!] Primary source failed for {cdn}: {e}" + Style.RESET_ALL)
                
                # Try alternative URL if available
                if 'alternative_url' in sources:
                    try:
                        print(Fore.CYAN + f"[*] Trying alternative source for {cdn}..." + Style.RESET_ALL)
                        alt_response = self.session.get(sources['alternative_url'], timeout=15)
                        alt_response.raise_for_status()
                        
                        if cdn == 'gcore':
                            ranges = [line.strip() for line in alt_response.text.split('\n') if line.strip() and not line.startswith('#')]
                        elif cdn == 'fastly':
                            ranges = [line.strip() for line in alt_response.text.split('\n') if line.strip() and not line.startswith('#')]
                        
                        success = True
                        print(Fore.GREEN + f"[+] Successfully updated {cdn} ranges from alternative source" + Style.RESET_ALL)
                        
                    except Exception as alt_e:
                        print(Fore.YELLOW + f"[!] Alternative source also failed for {cdn}: {alt_e}" + Style.RESET_ALL)
            
            # If all attempts failed, use fallback ranges
            if not success:
                print(Fore.YELLOW + f"[!] Using fallback ranges for {cdn}" + Style.RESET_ALL)
                ranges = sources['fallback']
            
            # Save to file
            filename = f"{cdn}.txt"
            try:
                with open(filename, 'w') as f:
                    f.write('\n'.join(ranges))
                
                # Update in-memory ranges
                self.cdn_ranges[cdn] = ranges
                
                print(Fore.GREEN + f"[+] Updated {cdn} ranges ({len(ranges)} entries)" + Style.RESET_ALL)
                
            except Exception as e:
                print(Fore.RED + f"[!] Error saving {cdn} ranges: {e}" + Style.RESET_ALL)
        
        # Save updated config
        self.save_config()
        input("\nPress Enter to return to menu...")

    def generate_html_report(self, results: List[Dict], filename: str) -> None:
        """Generate a comprehensive HTML report with sorting and filtering"""
        try:
            # Sort by ping time (lowest first)
            sorted_results = sorted(
                results,
                key=lambda x: float('inf') if x.get('ping') is None else x['ping']
            )
            
            # Create HTML content with UTF-8 encoding
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CDN Scanner Report By Jeet</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; cursor: pointer; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .good {{ color: green; }}
        .medium {{ color: orange; }}
        .bad {{ color: red; }}
    </style>
</head>
<body>
    <h1>CDN Scanner Report By Jeet</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total valid pairs: {len(sorted_results)}</p>
    
    <table id="resultsTable">
        <thead>
            <tr>
                <th onclick="sortTable(0)">IP</th>
                <th onclick="sortTable(1)">SNI</th>
                <th onclick="sortTable(2)">CDN</th>
                <th onclick="sortTable(3)">HTTPS</th>
                <th onclick="sortTable(4)">HTTP</th>
                <th onclick="sortTable(5)">Xray</th>
                <th onclick="sortTable(6)">Ping (ms)</th>
                <th onclick="sortTable(7)">SSL Time (ms)</th>
                <th onclick="sortTable(8)">HTTP Time (ms)</th>
                <th onclick="sortTable(9)">Server</th>
                <th onclick="sortTable(10)">Reverse DNS</th>
            </tr>
        </thead>
        <tbody>"""
            
            for result in sorted_results:
                # Safely get values with defaults and handle None values
                https_works = result.get('https_works', False)
                http_works = result.get('http_works', False)
                xray_works = result.get('xray_works', False)
                ip = result.get('ip', 'N/A')
                sni = result.get('sni', 'N/A')
                cdn = result.get('cdn', 'N/A')
                reverse_dns = ", ".join(result.get('reverse_dns', [])) or "None"
                server_header = result.get('server_header', 'N/A')
                
                https_class = "good" if https_works else "bad"
                http_class = "good" if http_works else "bad"
                xray_class = "good" if xray_works else "bad"
                
                # Handle None values for performance metrics
                ping = result.get('ping', 'N/A')
                ssl_time = result.get('ssl_handshake_time', 'N/A')
                http_time = result.get('http_response_time', 'N/A')
                
                # Format numeric values only if they're not None or 'N/A'
                if isinstance(ping, (int, float)):
                    ping = f"{ping:.1f}"
                if isinstance(ssl_time, (int, float)):
                    ssl_time = f"{ssl_time:.1f}"
                if isinstance(http_time, (int, float)):
                    http_time = f"{http_time:.1f}"
                
                html += f"""
            <tr>
                <td class="copyable" onclick="copyToClipboard(this)">{ip}</td>
                <td class="copyable" onclick="copyToClipboard(this)">{sni}</td>
                <td>{cdn}</td>
                <td class="{https_class}">{"✓" if https_works else "✗"}</td>
                <td class="{http_class}">{"✓" if http_works else "✗"}</td>
                <td class="{xray_class}">{"✓" if xray_works else "✗"}</td>
                <td>{ping}</td>
                <td>{ssl_time}</td>
                <td>{http_time}</td>
                <td>{server_header}</td>
                <td>{reverse_dns}</td>
            </tr>"""
            
            html += """
        </tbody>
    </table>
    <script>
        // Professional click-to-copy for IP and Reverse DNS columns
        document.querySelectorAll('td:nth-child(1), td:nth-child(2),td:nth-child(11)').forEach(td => {
            // Visual cues
            td.style.cursor = 'pointer';
            td.style.position = 'relative';
            td.title = 'Click to copy';
            
            td.addEventListener('click', () => {
                // Copy logic
                navigator.clipboard.writeText(td.textContent.trim());
                
                // Create tooltip
                const tooltip = document.createElement('div');
                tooltip.className = 'copy-tooltip';
                tooltip.textContent = 'Copied!';
                
                // Append and position
                td.appendChild(tooltip);
                
                // Auto-remove after 1s
                setTimeout(() => tooltip.remove(), 1000);
            });
        });
        
        function sortTable(column) {
            const table = document.getElementById("resultsTable");
            const rows = Array.from(table.rows).slice(1);
            const header = table.rows[0].cells[column];
            const direction = header.getAttribute("data-direction") || "asc";
            
            rows.sort((a, b) => {
                const aVal = a.cells[column].textContent;
                const bVal = b.cells[column].textContent;
                
                if (!isNaN(aVal) && !isNaN(bVal)) {
                    return direction === "asc" ? aVal - bVal : bVal - aVal;
                }
                return direction === "asc" 
                    ? aVal.localeCompare(bVal)
                    : bVal.localeCompare(aVal);
            });
            
            // Rebuild table
            rows.forEach(row => table.tBodies[0].appendChild(row));
            header.setAttribute("data-direction", direction === "asc" ? "desc" : "asc");
        }
    </script>
    <style>
        .copy-tooltip {
            position: absolute;
            bottom: calc(100% + 5px);
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: #fff;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-family: Arial, sans-serif;
            white-space: nowrap;
            z-index: 100;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            animation: fadeIn 0.15s ease-out;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateX(-50%) translateY(5px); }
            to { opacity: 1; transform: translateX(-50%) translateY(0); }
        }
    </style>
</body>
</html>"""
            
            # Write with explicit UTF-8 encoding
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
                
            print(Fore.GREEN + f"[+] HTML report saved to {filename}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error generating HTML report: {e}" + Style.RESET_ALL)
            logging.error(f"Error generating HTML report: {e}")

    def export_to_csv(self, results: List[Dict], filename: str) -> None:
        """Export results to CSV file"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'ip', 'sni', 'cdn', 'https_works', 'http_works', 'xray_works',
                    'ping', 'ssl_handshake_time', 'http_response_time',
                    'server_header', 'reverse_dns', 'timestamp'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    row = {
                        'ip': result.get('ip', ''),
                        'sni': result.get('sni', ''),
                        'cdn': result.get('cdn', ''),
                        'https_works': 'Yes' if result.get('https_works') else 'No',
                        'http_works': 'Yes' if result.get('http_works') else 'No',
                        'xray_works': 'Yes' if result.get('xray_works') else 'No',
                        'ping': result.get('ping', ''),
                        'ssl_handshake_time': result.get('ssl_handshake_time', ''),
                        'http_response_time': result.get('http_response_time', ''),
                        'server_header': result.get('server_header', ''),
                        'reverse_dns': ", ".join(result.get('reverse_dns', [])),
                        'timestamp': result.get('timestamp', '')
                    }
                    writer.writerow(row)
            
            print(Fore.GREEN + f"[+] Results exported to CSV: {filename}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error exporting to CSV: {e}" + Style.RESET_ALL)

    def export_to_excel(self, results: List[Dict], filename: str) -> None:
        """Export results to Excel file"""
        try:
            from openpyxl import Workbook
            
            wb = Workbook()
            ws = wb.active
            ws.title = "CDN Scan Results"
            
            # Write headers
            headers = [
                'IP', 'SNI', 'CDN', 'HTTPS Works', 'HTTP Works', 'Xray Works',
                'Ping (ms)', 'SSL Handshake (ms)', 'HTTP Response (ms)',
                'Server Header', 'Reverse DNS', 'Timestamp'
            ]
            ws.append(headers)
            
            # Write data
            for result in results:
                row = [
                    result.get('ip', ''),
                    result.get('sni', ''),
                    result.get('cdn', ''),
                    'Yes' if result.get('https_works') else 'No',
                    'Yes' if result.get('http_works') else 'No',
                    'Yes' if result.get('xray_works') else 'No',
                    result.get('ping', ''),
                    result.get('ssl_handshake_time', ''),
                    result.get('http_response_time', ''),
                    result.get('server_header', ''),
                    ", ".join(result.get('reverse_dns', [])),
                    result.get('timestamp', '')
                ]
                ws.append(row)
            
            # Save the file
            wb.save(filename)
            print(Fore.GREEN + f"[+] Results exported to Excel: {filename}" + Style.RESET_ALL)
        except ImportError:
            print(Fore.RED + "[!] openpyxl package not installed. Run: pip install openpyxl" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error exporting to Excel: {e}" + Style.RESET_ALL)

    def edit_configuration(self) -> None:
        """Allow user to edit configuration settings"""
        self.print_banner()
        print(Fore.CYAN + "Configuration Editor\n" + Style.RESET_ALL)
        
        print("Current Settings:")
        print(f"1. Debug Mode: {self.debug_mode}")
        print(f"2. Verbose Mode: {self.verbose_mode}")
        print(f"3. Rate Limit Delay: {self.rate_limit_delay}s")
        print(f"4. DNS Servers: {', '.join(self.dns_servers)}")
        print(f"5. Output Directory: {self.output_dir}")
        print(f"6. Proxy: {self.proxies.get('http') if self.proxies else 'None'}")
        print("\n7. Reload Configuration")
        print("8. Save Configuration")
        print("9. Return to Menu")
        
        try:
            choice = input("\nSelect option to change (1-9): ").strip()
            
            if choice == '1':
                self.debug_mode = not self.debug_mode
                print(Fore.YELLOW + f"\nDebug mode set to: {self.debug_mode}" + Style.RESET_ALL)
            elif choice == '2':
                self.verbose_mode = not self.verbose_mode
                print(Fore.YELLOW + f"\nVerbose mode set to: {self.verbose_mode}" + Style.RESET_ALL)
            elif choice == '3':
                try:
                    delay = float(input("Enter new rate limit delay (seconds): "))
                    if 0 <= delay <= 5:
                        self.rate_limit_delay = delay
                        print(Fore.GREEN + f"\nRate limit delay set to: {delay}s" + Style.RESET_ALL)
                    else:
                        print(Fore.RED + "\nDelay must be between 0 and 5 seconds" + Style.RESET_ALL)
                except ValueError:
                    print(Fore.RED + "\nInvalid input" + Style.RESET_ALL)
            elif choice == '4':
                new_servers = input("Enter new DNS servers (comma separated): ").strip()
                if new_servers:
                    self.dns_servers = [s.strip() for s in new_servers.split(',')]
                    print(Fore.GREEN + f"\nDNS servers updated to: {', '.join(self.dns_servers)}" + Style.RESET_ALL)
            elif choice == '5':
                new_dir = input("Enter new output directory: ").strip()
                if new_dir:
                    self.output_dir = new_dir
                    os.makedirs(self.output_dir, exist_ok=True)
                    print(Fore.GREEN + f"\nOutput directory set to: {new_dir}" + Style.RESET_ALL)
            elif choice == '6':
                proxy_url = input("Enter proxy URL (e.g., http://proxy:port or empty to disable): ").strip()
                if proxy_url:
                    self.configure_proxy(proxy_url)
                    print(Fore.GREEN + f"\nProxy set to: {proxy_url}" + Style.RESET_ALL)
                else:
                    self.proxies = None
                    self.session.proxies = None
                    print(Fore.GREEN + "\nProxy disabled" + Style.RESET_ALL)
            elif choice == '7':
                self.load_config()
                print(Fore.GREEN + "\nConfiguration reloaded" + Style.RESET_ALL)
            elif choice == '8':
                self.save_config()
                print(Fore.GREEN + "\nConfiguration saved" + Style.RESET_ALL)
            elif choice == '9':
                return
            else:
                print(Fore.RED + "\nInvalid choice" + Style.RESET_ALL)
            
            time.sleep(1)
            self.edit_configuration()
        except KeyboardInterrupt:
            return

    def save_config(self) -> None:
        """Save current configuration to file"""
        config = configparser.ConfigParser()
        
        config['DEFAULT'] = {
            'debug_mode': str(self.debug_mode),
            'verbose_mode': str(self.verbose_mode),
            'rate_limit_delay': str(self.rate_limit_delay),
            'dns_servers': ','.join(self.dns_servers),
            'output_dir': self.output_dir,
            'proxies': self.proxies.get('http') if self.proxies else ''
        }
        
        config['CDN_RANGES'] = {
            cdn: ','.join(ranges) for cdn, ranges in self.cdn_ranges.items()
        }
        
        try:
            with open(self.config_file, 'w') as configfile:
                config.write(configfile)
            logging.info("Configuration saved successfully")
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")
            print(Fore.RED + f"[!] Error saving configuration: {e}" + Style.RESET_ALL)

    def single_domain_scan(self) -> None:
        """Handle single domain scanning"""
        self.print_banner()
        print(Fore.CYAN + "Single Domain Scan\n" + Style.RESET_ALL)
        domain = input("Enter domain to scan (e.g., example.com): ").strip()
        
        if not domain:
            print(Fore.RED + "[!] No domain entered" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_file = os.path.join(self.output_dir, "valid_pairs.json")
        
        print(Fore.YELLOW + "\n[*] Starting scan..." + Style.RESET_ALL)
        self.start_time = time.time()
        
        valid_pairs = self.scan_domain(domain, output_file)
        
        elapsed = time.time() - self.start_time
        print(Fore.GREEN + f"\n[+] Scan completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        print(Fore.CYAN + f"Valid pairs found: {len(valid_pairs)}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Results saved to {output_file}" + Style.RESET_ALL)
        input("\nPress Enter to return to menu...")

    def test_xray_connection(self, ip: str, sni: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
        """Test if IP works with Xray/V2Ray by sending a test request"""
        try:
            # Create a simple Xray-like TLS request
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((ip, 443), timeout=timeout)
            with context.wrap_socket(sock, server_hostname=sni) as ssl_sock:
                # Send a fake HTTP request that Xray might use
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {sni}\r\n"
                    f"User-Agent: Xray/V2Ray\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                )
                ssl_sock.send(request.encode())
                
                # Check for response (Xray/V2Ray servers usually respond to this)
                response = ssl_sock.recv(1024)
                return b"HTTP/" in response or b"403" in response or b"404" in response
        except Exception as e:
            if self.debug_mode:
                print(Fore.YELLOW + f"[Xray Test Failed] {ip} - {e}" + Style.RESET_ALL)
            return False

    def xray_test_menu(self):
        """Test found IPs with Xray/V2Ray compatibility checks"""
        self.print_banner()
        print(Fore.CYAN + "Xray/V2Ray Compatibility Test\n" + Style.RESET_ALL)
        
        results_file = os.path.join(self.output_dir, "valid_pairs.json")
        if not os.path.exists(results_file):
            print(Fore.RED + "[!] No results file found. Run a scan first." + Style.RESET_ALL)
            input("\nPress Enter to return to menu...")
            return
        
        try:
            with open(results_file, 'r') as f:
                results = [json.loads(line) for line in f if line.strip()]
        except Exception as e:
            print(Fore.RED + f"[!] Error reading results: {e}" + Style.RESET_ALL)
            input("\nPress Enter to return to menu...")
            return
        
        if not results:
            print(Fore.YELLOW + "[!] No valid pairs found in results" + Style.RESET_ALL)
            input("\nPress Enter to return to menu...")
            return
        
        print(Fore.GREEN + f"\n[*] Found {len(results)} IPs to test for Xray compatibility" + Style.RESET_ALL)
        
        xray_working = []
        tested = 0
        
        for result in results:
            ip = result.get('ip')
            sni = result.get('sni')
            
            if not ip or not sni:
                continue
            
            print(Fore.CYAN + f"\n[*] Testing Xray compatibility: {sni} @ {ip}" + Style.RESET_ALL)
            
            if self.test_xray_connection(ip, sni):
                print(Fore.GREEN + f"[+] Xray WORKING: {sni} @ {ip}" + Style.RESET_ALL)
                result['xray_works'] = True
                xray_working.append(result)
            else:
                print(Fore.RED + f"[-] Xray FAILED: {sni} @ {ip}" + Style.RESET_ALL)
                result['xray_works'] = False
            
            tested += 1
            print(Fore.YELLOW + f"[*] Progress: {tested}/{len(results)} tested | Working: {len(xray_working)}" + Style.RESET_ALL)
        
        if xray_working:
            # Save Xray-working IPs separately
            xray_file = os.path.join(self.output_dir, "xray_working.json")
            xray_txt = os.path.join(self.output_dir, "xray_working.txt")
            
            with open(xray_file, 'w') as f:
                json.dump(xray_working, f, indent=2)
            
            # Save simplified version for easy copy-paste
            with open(xray_txt, 'w') as f:
                for item in xray_working:
                    f.write(f"{item['ip']} | {item['sni']} | Ping: {item.get('ping', 'N/A')}ms | CDN: {item.get('cdn', 'N/A')}\n")
            
            print(Fore.GREEN + f"\n[+] Found {len(xray_working)} Xray-compatible IPs!" + Style.RESET_ALL)
            print(Fore.GREEN + f"[+] Saved to: {xray_file}" + Style.RESET_ALL)
            print(Fore.GREEN + f"[+] Simplified list: {xray_txt}" + Style.RESET_ALL)
            
            # Update the original results file with Xray compatibility info
            with open(results_file, 'w') as f:
                for result in results:
                    f.write(json.dumps(result) + "\n")
        else:
            print(Fore.RED + "\n[!] No Xray-compatible IPs found" + Style.RESET_ALL)
        
        input("\nPress Enter to return to menu...")

    def _handle_keyboard_interrupt(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(Fore.RED + "\n[!] Operation cancelled by user" + Style.RESET_ALL)
        raise KeyboardInterrupt

    def __del__(self):
        """Clean up resources"""
        self.session.close()

    def run(self) -> None:
        """Main program loop with argument parsing"""
        parser = argparse.ArgumentParser(description='CDN SNI Scanner PLUS - Iran Optimized By Jeet')
        parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        parser.add_argument('-c', '--config', help='Specify alternative config file')
        parser.add_argument('-p', '--proxy', help='Specify proxy URL (e.g., http://proxy:port)')
        args = parser.parse_args()
        
        if args.config:
            self.config_file = args.config
        if args.debug:
            self.debug_mode = True
        if args.verbose:
            self.verbose_mode = True
        if args.proxy:
            self.configure_proxy(args.proxy)
        
        self.load_config()
        self.setup_logging()
        
        # Handle keyboard interrupt gracefully
        signal.signal(signal.SIGINT, self._handle_keyboard_interrupt)
        
        while True:
            try:
                self.print_menu()
                choice = input("Select an option (0-13): ").strip()
                
                if choice == '1':
                    self.single_domain_scan()
                elif choice == '2':
                    self.scan_random_ips()
                elif choice == '3':
                    self.run_file_scan()
                elif choice == '4':
                    self.view_results()
                elif choice == '5':
                    self.debug_mode = not self.debug_mode
                    logging.info(f"Debug mode {'enabled' if self.debug_mode else 'disabled'}")
                    print(Fore.YELLOW + f"\nDebug mode: {'ON' if self.debug_mode else 'OFF'}" + Style.RESET_ALL)
                    time.sleep(1)
                elif choice == '6':
                    self.test_known_cdns()
                elif choice == '7':
                    self.test_specific_cdn()
                elif choice == '8':
                    self.update_cdn_ranges()
                elif choice == '9':
                    # Swapped: Now Xray (Original 12 logic)
                    self.xray_test_menu()
                elif choice == '10':
                    # Swapped: Now Multi-Port (Original 13 logic)
                    self.scan_cloudflare_multiport()
                elif choice == '11':
                    # Swapped: Now HTML (Original 9 logic)
                    results_file = os.path.join(self.output_dir, "valid_pairs.json")
                    if os.path.exists(results_file):
                        with open(results_file, 'r') as f:
                            results = [json.loads(line) for line in f if line.strip()]
                        html_file = os.path.join(self.output_dir, "report.html")
                        self.generate_html_report(results, html_file)
                    else:
                        print(Fore.RED + "[!] No results file found" + Style.RESET_ALL)
                    input("\nPress Enter to return to menu...")
                elif choice == '12':
                    # Swapped: Now Configuration (Original 11 logic)
                    self.edit_configuration()
                elif choice == '13':
                    # Swapped: Now Export (Original 10 logic)
                    results_file = os.path.join(self.output_dir, "valid_pairs.json")
                    if os.path.exists(results_file):
                        with open(results_file, 'r') as f:
                            results = [json.loads(line) for line in f if line.strip()]
                        
                        print("\nExport Options:")
                        print("1. Export to CSV")
                        print("2. Export to Excel")
                        print("3. Export to both")
                        
                        export_choice = input("Select export format (1-3): ").strip()
                        
                        if export_choice == '1':
                            csv_file = os.path.join(self.output_dir, "cdn_results.csv")
                            self.export_to_csv(results, csv_file)
                        elif export_choice == '2':
                            excel_file = os.path.join(self.output_dir, "cdn_results.xlsx")
                            self.export_to_excel(results, excel_file)
                        elif export_choice == '3':
                            csv_file = os.path.join(self.output_dir, "cdn_results.csv")
                            excel_file = os.path.join(self.output_dir, "cdn_results.xlsx")
                            self.export_to_csv(results, csv_file)
                            self.export_to_excel(results, excel_file)
                        else:
                            print(Fore.RED + "[!] Invalid choice" + Style.RESET_ALL)
                    else:
                        print(Fore.RED + "[!] No results file found" + Style.RESET_ALL)
                    input("\nPress Enter to return to menu...")
                elif choice == '0':
                    print(Fore.CYAN + "\n[+] Exiting program..." + Style.RESET_ALL)
                    break
                else:
                    print(Fore.RED + "[!] Invalid choice" + Style.RESET_ALL)
                    time.sleep(1)
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] Operation cancelled by user" + Style.RESET_ALL)
                break
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                print(Fore.RED + f"[!] Unexpected error: {e}" + Style.RESET_ALL)
                time.sleep(2)

if __name__ == '__main__':
    try:
        scanner = CDNScannerPlus()
        scanner.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Program terminated by user" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Fatal error: {e}" + Style.RESET_ALL)
        input("Press Enter to exit...")


