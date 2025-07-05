import socket
import ssl
import concurrent.futures
import time
import dns.resolver
import json
import os
import random
from datetime import datetime
from ipaddress import ip_address, ip_network, IPv4Network
from colorama import init, Fore, Back, Style
import urllib3
import requests

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for Windows console colors
init(autoreset=True)

class CDNScannerPlus:
    def __init__(self):
        self.valid_pairs = []
        self.scanned_domains = 0
        self.total_tests = 0
        self.start_time = None
        self.debug_mode = False
        self.session = requests.Session()
        self.session.verify = False
        self.cdn_ranges = {
            'cloudflare': [],
            'fastly': [],
            'gcore': []
        }
        self.load_cdn_ranges()
        
        # Known working Gcore domains for testing
        self.gcore_test_domains = [
            'www.gcore.com',
            'gcore.lu',
            'cdn.gcorelabs.com',
            'api.gcore.com',
            'support.gcore.com'
        ]

    def load_cdn_ranges(self):
        """Load CDN ranges from files or use defaults"""
        for cdn in self.cdn_ranges:
            filename = f"{cdn}.txt"
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    self.cdn_ranges[cdn] = [line.strip() for line in f if line.strip()]
            else:
                # Default ranges if files don't exist
                self.cdn_ranges[cdn] = self.get_default_ranges(cdn)
    
    def get_default_ranges(self, cdn):
        """Return default IP ranges for each CDN (optimized for Iran)"""
        defaults = {
            'cloudflare': [
                '104.16.0.0/13', '172.64.0.0/13', '162.158.0.0/15', '108.162.192.0/18'
            ],
            'fastly': [
                '151.101.0.0/16', '199.232.0.0/16', '2a04:4e40::/32'
            ],
            'gcore': [
                '158.160.0.0/16', '92.223.84.0/24', '185.209.160.0/24'
            ]
        }
        return defaults.get(cdn, [])

    def clear_screen(self):
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        """Display program banner"""
        self.clear_screen()
        print(Fore.CYAN + r"""
   ____ ____  _   _   ____ ___ ____ _   _ _____ 
  / ___|  _ \| \ | | / ___|_ _/ ___| \ | |_   _|
 | |   | | | |  \| | \___ \| | |  _|  \| | | |  
 | |___| |_| | |\  |  ___) | | |_| | |\  | | |  
  \____|____/|_| \_| |____/___\____|_| \_| |_|  
        CDN SNI Scanner PLUS for V2Ray v3.1
        """ + Style.RESET_ALL)
        print(Fore.YELLOW + "Optimized for Iran - Gcore/Fastly/Cloudflare" + Style.RESET_ALL)

    def print_menu(self):
        """Display main menu"""
        self.print_banner()
        print(Fore.YELLOW + "[1]" + Style.RESET_ALL + " Scan single domain")
        print(Fore.YELLOW + "[2]" + Style.RESET_ALL + " Scan random IPs from CDN ranges")
        print(Fore.YELLOW + "[3]" + Style.RESET_ALL + " View saved results")
        print(Fore.YELLOW + "[4]" + Style.RESET_ALL + " Toggle debug mode (Current: " + 
              (Fore.GREEN + "ON" if self.debug_mode else Fore.RED + "OFF") + Style.RESET_ALL + ")")
        print(Fore.YELLOW + "[5]" + Style.RESET_ALL + " Test with known CDN domains (Gcore included)")
        print(Fore.YELLOW + "[6]" + Style.RESET_ALL + " Exit")
        print("\n")

    def is_ip_in_cdn_ranges(self, ip, cdn_name):
        """Check if IP belongs to CDN ranges"""
        try:
            ip_obj = ip_address(ip)
            for network in self.cdn_ranges.get(cdn_name.lower(), []):
                try:
                    if ip_obj in IPv4Network(network):
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            if self.debug_mode:
                print(Fore.RED + f"[DEBUG] Invalid IP address: {ip}" + Style.RESET_ALL)
            return False

    def resolve_domain(self, domain):
        """Resolve domain to IP addresses with multiple DNS servers"""
        dns_servers = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222']
        
        ips = set()
        for dns_server in dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                answers = resolver.resolve(domain, 'A')
                ips.update(str(r) for r in answers)
                if ips:
                    break
            except Exception as e:
                if self.debug_mode:
                    print(Fore.RED + f"[DEBUG] DNS resolution failed with {dns_server} for {domain}: {type(e).__name__}" + Style.RESET_ALL)
        
        return list(ips)

    def test_sni_pair(self, ip, sni, timeout=5):
        """Test if SNI + IP pair works with TLS"""
        self.total_tests += 1
        
        # Method 1: Direct SSL socket test
        try:
            sock = socket.create_connection((ip, 443), timeout=timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with context.wrap_socket(sock, server_hostname=sni) as ssl_sock:
                cert = ssl_sock.getpeercert()
                if cert:
                    if self.debug_mode:
                        print(Fore.GREEN + f"[DEBUG] SSL Success: {sni} @ {ip}" + Style.RESET_ALL)
                    return True
        except Exception as e:
            if self.debug_mode:
                print(Fore.RED + f"[DEBUG] SSL Failed for {sni} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)
        
        # Method 2: HTTP request test
        try:
            url = f"https://{ip}"
            headers = {'Host': sni}
            response = self.session.get(url, headers=headers, timeout=timeout, allow_redirects=False)
            if response.status_code in (200, 301, 302, 403):
                if self.debug_mode:
                    print(Fore.GREEN + f"[DEBUG] HTTP Success: {sni} @ {ip} (Status: {response.status_code})" + Style.RESET_ALL)
                return True
        except Exception as e:
            if self.debug_mode:
                print(Fore.RED + f"[DEBUG] HTTP Failed for {sni} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)
        
        return False

    def scan_domain(self, domain, output_file=None):
        """Scan a domain for valid SNI + IP pairs"""
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
            
            print(Fore.CYAN + f"[*] Found {len(cdn_ips)} {cdn_name} IPs for {domain}" + Style.RESET_ALL)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(self.test_sni_pair, ip, domain): (ip, domain, cdn_name) for ip in cdn_ips}
                
                for future in concurrent.futures.as_completed(futures):
                    ip, domain, cdn_name = futures[future]
                    try:
                        if future.result():
                            pair = {"ip": ip, "sni": domain, "cdn": cdn_name, "timestamp": datetime.now().isoformat()}
                            print(Fore.GREEN + f"[+] Valid pair found: {domain} @ {ip} ({cdn_name})" + Style.RESET_ALL)
                            valid_pairs.append(pair)
                            
                            if output_file:
                                self.save_result(pair, output_file)
                    except Exception as e:
                        print(Fore.RED + f"[!] Error testing {domain} @ {ip}: {type(e).__name__}" + Style.RESET_ALL)

        return valid_pairs

    def generate_random_ips(self, cidr, count):
        """Generate random IPs from a CIDR range"""
        network = IPv4Network(cidr)
        return [str(network[random.randint(0, network.num_addresses - 1)]) for _ in range(count)]

    def scan_random_ips(self):
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
        sni = input("Enter SNI hostname to test (e.g., example.com): ").strip()
        if not sni:
            print(Fore.RED + "[!] SNI hostname required" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_file = input("Enter output file name (default: valid_pairs.json): ").strip() or "valid_pairs.json"
        output_txt = output_file.replace('.json', '.txt')
        
        print(Fore.YELLOW + f"\n[*] Generating {ip_count} random IPs from {cdn_name} ranges..." + Style.RESET_ALL)
        
        # Generate random IPs
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
        
        # Save results to TXT
        if valid_pairs:
            self.save_to_txt(valid_pairs, output_txt)
        
        elapsed = time.time() - self.start_time
        print(Fore.GREEN + f"\n[+] Scan completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        print(Fore.CYAN + f"Valid pairs found: {len(valid_pairs)}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] JSON results saved to {output_file}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] TXT results saved to {output_txt}" + Style.RESET_ALL)
        input("\nPress Enter to return to menu...")

    def save_result(self, pair, output_file):
        """Save a valid pair to output file (JSON)"""
        try:
            with open(output_file, 'a') as f:
                f.write(json.dumps(pair) + "\n")
        except IOError as e:
            print(Fore.RED + f"[!] Failed to save results: {e}" + Style.RESET_ALL)

    def save_to_txt(self, results, filename):
        """Save results to a TXT file"""
        try:
            with open(filename, 'w') as f:
                for result in results:
                    f.write(f"IP: {result['ip']}\n")
                    f.write(f"SNI: {result['sni']}\n")
                    f.write(f"CDN: {result['cdn']}\n")
                    f.write(f"Timestamp: {result['timestamp']}\n")
                    f.write("-" * 40 + "\n")
            print(Fore.GREEN + f"[+] TXT results saved to {filename}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error saving TXT file: {e}" + Style.RESET_ALL)

    def view_results(self, results_file='valid_pairs.json'):
        """Display saved results"""
        self.print_banner()
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

    def test_known_cdns(self):
        """Test with known CDN domains including Gcore-specific domains"""
        test_domains = [
            ('www.cloudflare.com', 'cloudflare'),
            ('www.fastly.com', 'fastly'),
            *[(domain, 'gcore') for domain in self.gcore_test_domains]
        ]
        
        print(Fore.CYAN + "\n[*] Testing with known CDN domains..." + Style.RESET_ALL)
        self.start_time = time.time()
        
        all_results = []
        for domain, expected_cdn in test_domains:
            print(Fore.YELLOW + f"\n[*] Testing {domain} (expected: {expected_cdn})" + Style.RESET_ALL)
            valid_pairs = self.scan_domain(domain)
            
            if valid_pairs:
                print(Fore.GREEN + f"[+] Found {len(valid_pairs)} valid pairs for {domain}" + Style.RESET_ALL)
                for pair in valid_pairs:
                    print(f"  - {pair['ip']} ({pair['cdn']})")
                all_results.extend(valid_pairs)
            else:
                print(Fore.RED + f"[!] No valid pairs found for {domain}" + Style.RESET_ALL)
        
        # Save results to both JSON and TXT
        if all_results:
            output_json = "known_cdn_results.json"
            output_txt = "known_cdn_results.txt"
            
            with open(output_json, 'w') as f:
                json.dump(all_results, f, indent=2)
            
            self.save_to_txt(all_results, output_txt)
            
            print(Fore.GREEN + f"\n[+] JSON results saved to {output_json}" + Style.RESET_ALL)
            print(Fore.GREEN + f"[+] TXT results saved to {output_txt}" + Style.RESET_ALL)
        
        elapsed = time.time() - self.start_time
        print(Fore.CYAN + f"\n[*] Test completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
        input("\nPress Enter to return to menu...")

    def run_single_scan(self):
        """Handle single domain scanning"""
        self.print_banner()
        print(Fore.CYAN + "Single Domain Scan\n" + Style.RESET_ALL)
        domain = input("Enter domain to scan (e.g., example.com): ").strip()
        
        if not domain:
            print(Fore.RED + "[!] No domain entered" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_file = input("Enter output file name (default: valid_pairs.json): ").strip() or "valid_pairs.json"
        output_txt = output_file.replace('.json', '.txt')
        
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

    def run_file_scan(self):
        """Handle scanning from file"""
        self.print_banner()
        print(Fore.CYAN + "Batch Domain Scan\n" + Style.RESET_ALL)
        input_file = input("Enter path to domains file: ").strip()
        
        if not input_file:
            print(Fore.RED + "[!] No file specified" + Style.RESET_ALL)
            time.sleep(2)
            return
        
        output_file = input("Enter output file name (default: valid_pairs.json): ").strip() or "valid_pairs.json"
        output_txt = output_file.replace('.json', '.txt')
        
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

    def load_domains_from_file(self, file_path):
        """Load domains from a text file with error handling"""
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(Fore.RED + f"[!] File not found: {file_path}" + Style.RESET_ALL)
            return []
        except Exception as e:
            print(Fore.RED + f"[!] Error reading file: {e}" + Style.RESET_ALL)
            return []

    def main(self):
        """Main program loop"""
        while True:
            try:
                self.print_menu()
                choice = input("Select an option (1-6): ").strip()
                
                if choice == '1':
                    self.run_single_scan()
                elif choice == '2':
                    self.scan_random_ips()
                elif choice == '3':
                    self.view_results()
                elif choice == '4':
                    self.debug_mode = not self.debug_mode
                    print(Fore.YELLOW + f"\nDebug mode is now {'ON' if self.debug_mode else 'OFF'}" + Style.RESET_ALL)
                    time.sleep(1)
                elif choice == '5':
                    self.test_known_cdns()
                elif choice == '6':
                    print(Fore.CYAN + "\n[+] Exiting program..." + Style.RESET_ALL)
                    break
                else:
                    print(Fore.RED + "[!] Invalid choice" + Style.RESET_ALL)
                    time.sleep(1)
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] Operation cancelled by user" + Style.RESET_ALL)
                break
            except Exception as e:
                print(Fore.RED + f"[!] Unexpected error: {e}" + Style.RESET_ALL)
                time.sleep(3)

if __name__ == '__main__':
    try:
        scanner = CDNScannerPlus()
        scanner.main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Program terminated by user" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Fatal error: {e}" + Style.RESET_ALL)
        input("Press Enter to exit...")