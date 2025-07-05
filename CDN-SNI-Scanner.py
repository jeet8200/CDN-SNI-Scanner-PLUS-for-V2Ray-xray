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
from typing import List, Dict, Tuple, Optional, Union
import configparser
import argparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for Windows console colors
init(autoreset=True)

class CDNScannerPlus:
    def __init__(self, config_file: str = 'config.ini'):
        # Initialize test domains first
        self.gcore_test_domains = [
            'gcore.com', 'www.gcore.com', 'images.gcore.com',
            'static.gcore.com', 'api.gcore.com', 'cdn.gcdn.co',
            'cdn.gcorelabs.com', 'demo-cdn.gcore.com'
        ]
        
        self.cdn_test_domains = {
            'cloudflare': ['www.cloudflare.com', 'cloudflare.com'],
            'fastly': ['www.fastly.com', 'fastly.com'],
            'gcore': self.gcore_test_domains,
            'akamai': ['www.akamai.com', 'akamai.com'],
            'cloudfront': ['aws.amazon.com', 'd1.awsstatic.com']
        }

        # Initialize other attributes
        self.valid_pairs = []
        self.scanned_domains = 0
        self.total_tests = 0
        self.start_time = None
        self.debug_mode = False
        self.verbose_mode = False
        self.rate_limit_delay = 0.1  # seconds between requests
        self.session = requests.Session()
        self.session.verify = False
        self.config_file = config_file
        self.cdn_ranges = {}
        self.dns_servers = []
        
        # Load configuration and setup
        self.load_config()
        self.setup_logging()

    def load_config(self) -> None:
        """Load configuration from file or set defaults"""
        config = configparser.ConfigParser()
        
        # Default configuration
        config['DEFAULT'] = {
            'debug_mode': 'False',
            'verbose_mode': 'False',
            'rate_limit_delay': '0.1',
            'dns_servers': '1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222',
            'output_dir': 'results'
        }
        
        # Default CDN ranges
        config['CDN_RANGES'] = {
            'cloudflare': '104.16.0.0/13,172.64.0.0/13,162.158.0.0/15,108.162.192.0/18',
            'fastly': '151.101.0.0/16,199.232.0.0/16,2a04:4e40::/32',
            'gcore': '158.160.0.0/16,92.223.84.0/24,185.209.160.0/24,45.133.144.0/24,45.135.240.0/22',
            'akamai': '23.0.0.0/12,95.100.0.0/15,184.24.0.0/13',
            'cloudfront': '13.32.0.0/15,13.224.0.0/14'
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
            self.rate_limit_delay = config.getfloat('DEFAULT', 'rate_limit_delay', fallback=0.1)
            self.dns_servers = [s.strip() for s in config.get('DEFAULT', 'dns_servers').split(',')]
            self.output_dir = config.get('DEFAULT', 'output_dir', fallback='results')
            
            # Create output directory if it doesn't exist
            os.makedirs(self.output_dir, exist_ok=True)
            
            # Load CDN ranges
            self.cdn_ranges = {cdn: [r.strip() for r in ranges.split(',')] 
                             for cdn, ranges in config['CDN_RANGES'].items()}
            
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

    def setup_logging(self) -> None:
        """Configure logging system"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        level = logging.DEBUG if self.debug_mode else logging.INFO
        
        logging.basicConfig(
            level=level,
            format=log_format,
            filename='cdn_scanner.log',
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
        CDN SNI Scanner PLUS - ENHANCED VERSION
        """ + Style.RESET_ALL)
        print(Fore.YELLOW + "Multi-CDN Support | IPv6 Ready | Advanced Configuration" + Style.RESET_ALL)

    def print_menu(self) -> None:
        """Display the main menu"""
        self.print_banner()
        print(Fore.YELLOW + "[1]" + Style.RESET_ALL + " Scan single domain")
        print(Fore.YELLOW + "[2]" + Style.RESET_ALL + " Scan random IPs")
        print(Fore.YELLOW + "[3]" + Style.RESET_ALL + " Scan from file")
        print(Fore.YELLOW + "[4]" + Style.RESET_ALL + " View results")
        print(Fore.YELLOW + "[5]" + Style.RESET_ALL + " Toggle debug")
        print(Fore.YELLOW + "[6]" + Style.RESET_ALL + " Test known CDNs")
        print(Fore.YELLOW + "[7]" + Style.RESET_ALL + " Deep CDN Test")
        print(Fore.YELLOW + "[8]" + Style.RESET_ALL + " Configuration")
        print(Fore.YELLOW + "[9]" + Style.RESET_ALL + " Exit")
        print("\n")

    def run_single_scan(self) -> None:
        """Handle single domain scanning"""
        self.print_banner()
        print(Fore.CYAN + "Single Domain Scan\n" + Style.RESET_ALL)
        domain = input("Enter domain to scan (e.g., example.com): ").strip()
        
        if not domain:
            print(Fore.RED + "[!] No domain entered" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_file = os.path.join(self.output_dir, "valid_pairs.json")
        output_txt = os.path.join(self.output_dir, "valid_pairs.txt")
        
        print(Fore.YELLOW + "\n[*] Starting scan..." + Style.RESET_ALL)
        self.start_time = time.time()
        
        valid_pairs = self.scan_domain(domain, output_file)
        
        # Save to TXT
        if valid_pairs:
            self.save_to_txt(valid_pairs, output_txt)
        
        elapsed = time.time() - self.start_time
        print(Fore.GREEN + f"\n[+] Scan completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        print(Fore.CYAN + f"Valid pairs found: {len(valid_pairs)}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] JSON results saved to {output_file}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] TXT results saved to {output_txt}" + Style.RESET_ALL)
        input("\nPress Enter to return to menu...")

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
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(self.test_sni_pair, ip, domain): (ip, domain, cdn_name) for ip in cdn_ips}
                
                for future in concurrent.futures.as_completed(futures):
                    ip, domain, cdn_name = futures[future]
                    try:
                        if future.result():
                            pair = {
                                "ip": ip,
                                "sni": domain,
                                "cdn": cdn_name,
                                "timestamp": datetime.now().isoformat()
                            }
                            print(Fore.GREEN + f"[+] Valid: {domain} @ {ip} ({cdn_name})" + Style.RESET_ALL)
                            valid_pairs.append(pair)
                            if output_file:
                                self.save_result(pair, output_file)
                    except Exception as e:
                        print(Fore.RED + f"[!] Error testing {domain} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)
        return valid_pairs

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

    def test_sni_pair(self, ip: str, sni: str, timeout: int = 5) -> bool:
        """Test if IP accepts the SNI"""
        self.total_tests += 1
        time.sleep(self.rate_limit_delay)
        
        # SSL/TLS test
        try:
            sock = socket.create_connection((ip, 443), timeout=timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with context.wrap_socket(sock, server_hostname=sni) as ssl_sock:
                cert = ssl_sock.getpeercert()
                if cert:
                    if self.verbose_mode:
                        print(Fore.CYAN + f"[*] SSL cert found for {sni} @ {ip}" + Style.RESET_ALL)
                    return True
        except Exception as e:
            logging.debug(f"SSL failed for {sni} @ {ip}: {e}")
            if self.debug_mode:
                print(Fore.RED + f"[DEBUG] SSL failed for {sni} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)
        
        # HTTP test
        try:
            response = self.session.get(
                f"https://{ip}",
                headers={'Host': sni},
                timeout=timeout,
                allow_redirects=False,
                verify=False
            )
            
            if response.status_code in (200, 301, 302, 403, 404):
                if self.verbose_mode:
                    print(Fore.CYAN + f"[*] HTTP {response.status_code} for {sni} @ {ip}" + Style.RESET_ALL)
                return True
        except Exception as e:
            logging.debug(f"HTTP failed for {sni} @ {ip}: {e}")
            if self.debug_mode:
                print(Fore.RED + f"[DEBUG] HTTP failed for {sni} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)
        
        return False

    def save_result(self, pair: Dict, output_file: str) -> None:
        """Save a valid pair to output file"""
        try:
            with open(output_file, 'a') as f:
                f.write(json.dumps(pair) + "\n")
        except IOError as e:
            print(Fore.RED + f"[!] Failed to save results: {e}" + Style.RESET_ALL)

    def save_to_txt(self, results: List[Dict], filename: str) -> None:
        """Save results to TXT file"""
        try:
            with open(filename, 'w') as f:
                for result in results:
                    f.write(f"IP: {result['ip']}\n")
                    f.write(f"SNI: {result['sni']}\n")
                    f.write(f"CDN: {result['cdn']}\n")
                    f.write(f"Timestamp: {result['timestamp']}\n")
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
                    print(f"{i}. {pair['sni']} @ {pair['ip']} ({pair['cdn']}) - {pair['timestamp']}")
                
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
            choice = int(input("Enter choice (1-5): ")) - 1
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
        sni = input("Enter SNI hostname to test (e.g., example.com): ").strip()
        if not sni:
            print(Fore.RED + "[!] SNI hostname required" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_file = os.path.join(self.output_dir, "valid_pairs.json")
        output_txt = os.path.join(self.output_dir, "valid_pairs.txt")
        
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.test_sni_pair, ip, sni): ip for ip in test_ips}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                ip = futures[future]
                try:
                    if future.result():
                        pair = {"ip": ip, "sni": sni, "cdn": cdn_name, "timestamp": datetime.now().isoformat()}
                        print(Fore.GREEN + f"[+] Valid pair found: {sni} @ {ip} ({cdn_name})" + Style.RESET_ALL)
                        valid_pairs.append(pair)
                        
                        if output_file:
                            self.save_result(pair, output_file)
                except Exception as e:
                    print(Fore.RED + f"[!] Error testing {sni} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)
                
                # Progress update
                if i % 10 == 0 or i == len(test_ips):
                    elapsed = time.time() - self.start_time
                    print(Fore.CYAN + f"[*] Progress: {i}/{len(test_ips)} IPs tested | Found: {len(valid_pairs)} | Elapsed: {elapsed:.1f}s" + Style.RESET_ALL)
        
        # Save to TXT
        if valid_pairs:
            self.save_to_txt(valid_pairs, output_txt)
        
        elapsed = time.time() - self.start_time
        print(Fore.GREEN + f"\n[+] Scan completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        print(Fore.CYAN + f"Valid pairs found: {len(valid_pairs)}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] JSON results saved to {output_file}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] TXT results saved to {output_txt}" + Style.RESET_ALL)
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
        output_txt = os.path.join(self.output_dir, "valid_pairs.txt")
        
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
        
        # Save to TXT
        if all_valid_pairs:
            self.save_to_txt(all_valid_pairs, output_txt)
        
        elapsed = time.time() - self.start_time
        print(Fore.GREEN + f"\n[+] Scan completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        print(Fore.CYAN + f"Total valid pairs found: {len(all_valid_pairs)}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] JSON results saved to {output_file}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] TXT results saved to {output_txt}" + Style.RESET_ALL)
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
                        print(f"  - {pair['ip']} ({pair['cdn']})")
                    all_results.extend(valid_pairs)
                else:
                    print(Fore.RED + f"[!] No valid pairs found for {domain}" + Style.RESET_ALL)
        
        # Save results
        if all_results:
            output_json = os.path.join(self.output_dir, "known_cdn_results.json")
            output_txt = os.path.join(self.output_dir, "known_cdn_results.txt")
            
            with open(output_json, 'w') as f:
                json.dump(all_results, f, indent=2)
            
            self.save_to_txt(all_results, output_txt)
            
            print(Fore.GREEN + f"\n[+] JSON results saved to {output_json}" + Style.RESET_ALL)
            print(Fore.GREEN + f"[+] TXT results saved to {output_txt}" + Style.RESET_ALL)
        
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
            choice = int(input("Enter choice (1-5): ")) - 1
            cdn_name = list(self.cdn_test_domains.keys())[choice]
            test_domains = self.cdn_test_domains[cdn_name]
        except:
            print(Fore.RED + "[!] Invalid choice" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_json = os.path.join(self.output_dir, f"{cdn_name}_results.json")
        output_txt = os.path.join(self.output_dir, f"{cdn_name}_results.txt")
        
        all_results = []
        for domain in test_domains:
            print(Fore.YELLOW + f"\n[*] Testing: {domain}" + Style.RESET_ALL)
            ips = self.resolve_domain(domain)
            print(Fore.CYAN + f"[*] Resolved IPs: {ips}" + Style.RESET_ALL)
            
            for ip in ips:
                if self.test_sni_pair(ip, domain):
                    pair = {
                        "ip": ip,
                        "sni": domain,
                        "cdn": cdn_name,
                        "timestamp": datetime.now().isoformat()
                    }
                    print(Fore.GREEN + f"[+] Valid {cdn_name}: {domain} @ {ip}" + Style.RESET_ALL)
                    all_results.append(pair)
                else:
                    print(Fore.RED + f"[-] Failed: {domain} @ {ip}" + Style.RESET_ALL)
        
        # Save results
        if all_results:
            with open(output_json, 'w') as f:
                json.dump(all_results, f, indent=2)
            
            self.save_to_txt(all_results, output_txt)
            
            print(Fore.GREEN + f"\n[+] JSON results saved to {output_json}" + Style.RESET_ALL)
            print(Fore.GREEN + f"[+] TXT results saved to {output_txt}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "\n[!] No valid pairs found" + Style.RESET_ALL)
        
        input("\nPress Enter to return to menu...")

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
        print("\n6. Reload Configuration")
        print("7. Save Configuration")
        print("8. Return to Menu")
        
        try:
            choice = input("\nSelect option to change (1-8): ").strip()
            
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
                self.load_config()
                print(Fore.GREEN + "\nConfiguration reloaded" + Style.RESET_ALL)
            elif choice == '7':
                self.save_config()
                print(Fore.GREEN + "\nConfiguration saved" + Style.RESET_ALL)
            elif choice == '8':
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
            'output_dir': self.output_dir
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

    def main(self) -> None:
        """Main program loop with argument parsing"""
        parser = argparse.ArgumentParser(description='CDN SNI Scanner PLUS')
        parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        parser.add_argument('-c', '--config', help='Specify alternative config file')
        args = parser.parse_args()
        
        if args.config:
            self.config_file = args.config
        if args.debug:
            self.debug_mode = True
        if args.verbose:
            self.verbose_mode = True
        
        self.load_config()
        self.setup_logging()
        
        while True:
            try:
                self.print_menu()
                choice = input("Select an option (1-9): ").strip()
                
                if choice == '1':
                    self.run_single_scan()
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
                    self.edit_configuration()
                elif choice == '9':
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
        scanner.main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Program terminated by user" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Fatal error: {e}" + Style.RESET_ALL)
        input("Press Enter to exit...")