import subprocess
import os
import random
import sys
import ipaddress
import time
import socket
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CORE SETTINGS ---
DEFAULT_TIMEOUT = 30
DEFAULT_THREADS = 20
MY_WORKING_SNIS = ["kubernetes.io", "letsencrypt.org"]
MY_WORKING_IP = "104.198.14.52"
SMART_LOG = "smart_subnets.txt"
RESULTS_DIR = "results"

# --- UI COLORS & WINDOWS INITIALIZATION ---
if os.name == 'nt':
    os.system('color')

C_CYAN, C_GREEN, C_YELLOW, C_RED, C_MAGENTA, BOLD, RESET, C_GRAY = (
    "\033[96m", "\033[92m", "\033[93m", "\033[91m", "\033[95m", "\033[1m", "\033[0m", "\033[90m"
)

if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

subnet_lock = threading.Lock()
alive_ips_lock = threading.Lock()  # Thread-safety for pre-screening array modifications

# --- HELPER: WINDOWS SAFE LINE CLEAR ---
def clear_line(text=""):
    """Safely clears the line on Windows and prints new text without residual artifacts."""
    if os.name == 'nt':
        sys.stdout.write("\r" + " " * 79 + "\r" + text)
    else:
        sys.stdout.write(f"\r\033[K{text}")
    sys.stdout.flush()

# --- HELPER: FILE PARSER ---
def parse_list(f, fb):
    p = os.path.join(os.path.dirname(__file__), f)
    if os.path.exists(p):
        with open(p, 'r', encoding='utf-8') as file:
            l = [i.strip() for i in file if i.strip()]
            return list(dict.fromkeys(l))
    return fb

# --- LOAD DATA ---
FULL_IP_LIST = parse_list("ips.txt", ["15.197.167.90", "50.7.85.38", "188.114.97.3"])
FULL_SNI_LIST = parse_list("sni.txt", ["kubernetes.io", "helm.sh", "istio.io", "calico.org", "argo-cd.readthedocs.io", "vuejs.org", "smashingmagazine.com", "k8s.io", "letsencrypt.org"])

BASE_NETLIFY_RANGES = [
    "50.7.4.0/24",     # Primary Netlify Anycast
    "50.7.87.0/24",    # Secondary Netlify Anycast
    "15.197.167.0/24", # AWS Global Accelerator (Netlify Entry)
    "3.33.186.0/24",   # AWS Global Accelerator (Netlify Entry)
    "75.2.60.0/22",    # AWS Netlify Edge
    "99.83.231.0/24",  # AWS Netlify Edge
    "104.198.14.0/24", # GCP Netlify Edge
    "44.217.161.0/24", # AWS US-East-1 Netlify
    "103.42.64.0/23",  # Netlify APAC
    "104.156.20.0/22", # Netlify US/EU
    "185.31.160.0/22", # Netlify Global
    "192.230.34.0/24", # Netlify US
    "216.160.83.0/24", # Netlify US
    "167.99.0.0/16",   # DigitalOcean
    "138.197.0.0/16",  # DigitalOcean
    "104.248.0.0/16",  # DigitalOcean
    "34.107.128.0/17",
    "15.197.160.0/20",
    "54.176.0.0/15",
    "184.105.99.0/24",
    "63.176.0.0/14",
    "35.156.0.0/14",
    "74.125.128.0/17",
    "52.222.176.0/21"
]

def load_smart_ranges():
    ranges = set(BASE_NETLIFY_RANGES)
    if os.path.exists(SMART_LOG):
        with open(SMART_LOG, 'r', encoding='utf-8') as f:
            for line in f:
                val = line.strip()
                if val: 
                    ranges.add(val)
    return list(ranges)

def save_smart_subnet(ip):
    try:
        subnet = ".".join(ip.split('.')[:3]) + ".0/24"
        with subnet_lock:
            existing = set()
            if os.path.exists(SMART_LOG):
                with open(SMART_LOG, 'r', encoding='utf-8') as f:
                    existing = {line.strip() for line in f}
            if subnet not in existing and subnet not in BASE_NETLIFY_RANGES:
                with open(SMART_LOG, 'a', encoding='utf-8') as f:
                    f.write(subnet + "\n")
                return True
    except Exception:
        pass
    return False

def get_ping(ip):
    start = time.time()
    try:
        s = socket.create_connection((ip, 443), timeout=4)
        s.close()
        return round((time.time() - start) * 1000)
    except Exception: 
        return None

def analyze_protocol(ip, sni, mode_name):
    ping = get_ping(ip)
    if not ping: 
        return {"ip": ip, "sni": sni, "ping": None, "status": "DEAD", "h2": "NO", "tls": "None"}

    cmd = [
        "curl", "-s", "-k", "-o", os.devnull, "-L", 
        "--connect-timeout", "4", 
        "-m", str(DEFAULT_TIMEOUT), 
        "--resolve", f"{sni}:443:{ip}", 
        "-w", "%{http_code}|%{http_version}|%{ssl_verify_result}", 
        f"https://{sni}"
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DEFAULT_TIMEOUT+2)
        output = proc.stdout.strip()
        
        if not output:
            return {"ip": ip, "sni": sni, "ping": ping, "status": "NO_OUTPUT", "h2": "NO", "tls": "None"}
            
        raw = output.split('|')
        if len(raw) < 3 or raw[0] == "000": 
            return {"ip": ip, "sni": sni, "ping": ping, "status": "???", "h2": "NO", "tls": "None"}

        status = raw[0]
        http_ver = raw[1] if len(raw) > 1 else ""

        if status in ["200", "403"]: 
            save_smart_subnet(ip)

        return {
            "ip": ip, 
            "sni": sni, 
            "ping": ping, 
            "status": status, 
            "h2": "YES" if "2" in http_ver else "NO", 
            "tls": "Verified" if len(raw) > 2 and raw[2] == "0" else "Unverified"
        }
    except subprocess.TimeoutExpired:
        return {"ip": ip, "sni": sni, "ping": ping, "status": "TIMEOUT", "h2": "NO", "tls": "None"}
    except Exception: 
        return {"ip": ip, "sni": sni, "ping": ping, "status": "ERROR", "h2": "NO", "tls": "None"}


def generate_final_outputs(results, mode_name):
    """Asks the user for a custom name prefix/suffix and saves both HTML and TXT logs simultaneously."""
    print(f"\n{BOLD}{C_YELLOW}--- EXPORT MANAGER ---{RESET}")
    custom_name = input(f"{BOLD}Enter a custom tag/name to append to the filename & title (Optional): {RESET}").strip()
    
    if custom_name:
        sanitized_suffix = "".join(x for x in custom_name if x.isalnum() or x in "._-").strip()
        file_base = f"{mode_name}_{sanitized_suffix}"
        display_title = f"{mode_name} ({custom_name})"
    else:
        file_base = mode_name
        display_title = mode_name

    txt_filename = os.path.join(RESULTS_DIR, f"{file_base}_All_Found.txt")
    html_filename = os.path.join(RESULTS_DIR, f"{file_base}_Results.html")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(txt_filename, "w", encoding='utf-8') as f:
            f.write(f"# Scan Session: {display_title} | Timestamp: {timestamp}\n")
            for r in results:
                f.write(f"IP: {r['ip']} | SNI: {r['sni']} | Status: {r['status']} | Ping: {r['ping']}ms\n")
        print(f"{C_GREEN}[+] Text logs saved successfully: {txt_filename}{RESET}")
    except Exception as e:
        print(f"{C_RED}[!] Failed writing text asset logs: {e}{RESET}")

    grouped_nodes = {}
    for r in results:
        ip = r['ip']
        if ip not in grouped_nodes:
            grouped_nodes[ip] = {"ip": ip, "status": r['status'], "snis_data": []}
        if not any(d['name'] == r['sni'] for d in grouped_nodes[ip]['snis_data']):
            grouped_nodes[ip]['snis_data'].append({"name": r['sni'], "ping": r['ping']})

    for ip in grouped_nodes:
        grouped_nodes[ip]['snis_data'].sort(key=lambda x: x['ping'] or 9999)
        grouped_nodes[ip]['best_ping'] = grouped_nodes[ip]['snis_data'][0]['ping']

    sorted_ips = sorted(grouped_nodes.values(), key=lambda x: x['best_ping'] or 9999)
    
    html_template = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{display_title} Sorted Results</title>
    <style>
        body {{ font-family: sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        .card-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 15px; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; display: flex; flex-direction: column; justify-content: space-between; }}
        .status {{ float: right; font-weight: bold; padding: 2px 8px; border-radius: 4px; margin-left: 5px; }}
        .s200 {{ color: #3fb950; background: rgba(63, 185, 80, 0.1); }}
        .s403 {{ color: #db6d28; background: rgba(219, 109, 40, 0.1); }}
        .val {{ font-family: monospace; display: block; background: #0d1117; padding: 6px; margin: 5px 0; border-radius: 4px; cursor: pointer; border: 1px solid #21262d; word-break: break-all; }}
        .val:hover {{ border-color: #58a6ff; }}
        .sni-container {{ background: #21262d; padding: 8px; border-radius: 6px; margin: 8px 0; }}
        .sni-row {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; padding-bottom: 4px; border-bottom: 1px dashed #30363d; }}
        .sni-row:last-child {{ margin-bottom: 0; padding-bottom: 0; border-bottom: none; }}
        .ping-tag {{ background: #1f6feb; color: white; padding: 1px 5px; font-size: 11px; font-weight: bold; border-radius: 3px; margin-left: auto; margin-right: 8px; font-family: monospace; }}
        .btn {{ background: #238636; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; }}
        .btn:hover {{ background: #2ea043; }}
        .btn-main {{ background: #1f6feb; width: 100%; padding: 8px; margin-top: 8px; font-weight: bold; font-size: 14px; }}
        .btn-main:hover {{ background: #388bfd; }}
    </style>
    <script>function copy(t, e) {{ navigator.clipboard.writeText(t); let o = e.innerText; e.innerText = "COPIED!"; setTimeout(() => e.innerText = o, 1000); }}</script>
    </head><body><h1>🚀 {display_title} Dashboard By JeeThM && G </h1><p>Unique Active IPs: {len(sorted_ips)} | Last Updated: {timestamp}</p><div class="card-grid">"""
    
    for item in sorted_ips:
        s_c = "s200" if item['status'] == "200" else "s403"
        html_template += f"""
        <div class="card">
            <div>
                <span class="status {s_c}">HTTP {item['status']}</span>
                <small style="color: #8b949e;">IP ADDRESS</small>
                <div class="val" onclick="copy('{item['ip']}', this)">{item['ip']}</div>
                <small style="color: #8b949e;">WORKING MASK SNIs ({len(item['snis_data'])})</small>
                <div class="sni-container">"""
        for sni_obj in item['snis_data']:
            html_template += f"""
                    <div class="sni-row">
                        <span style="font-family: monospace; font-size: 13px; color: #58a6ff;">{sni_obj['name']}</span>
                        <span class="ping-tag">{sni_obj['ping'] or 'N/A'}ms</span>
                        <button class="btn" onclick="copy('{sni_obj['name']}', this)">Copy SNI</button>
                    </div>"""
        html_template += f"""
                </div>
            </div>
            <div>
                <div style="margin-top: 5px;">Best Card Ping: <b style="color:#3fb950">{item['best_ping'] or 'N/A'}ms</b></div>
                <button class="btn btn-main" onclick="copy('{item['ip']}', this)">Copy IP Address</button>
            </div>
        </div>"""
    html_template += "</div></body></html>"
    
    with open(html_filename, "w", encoding="utf-8") as f: 
        f.write(html_template)
    print(f"{C_CYAN}[+] Dashboard layout saved successfully: {html_filename}{RESET}")


def get_safe_random_hosts(cidr_str, max_count):
    """Safely extracts random hosts from a subnet without exploding system memory."""
    try:
        # Handles standalone standard raw IPs missing masking notation
        if '/' not in cidr_str:
            return [str(ipaddress.IPv4Address(cidr_str))]
            
        net = ipaddress.IPv4Network(cidr_str, strict=False)
        total_ips = net.num_addresses
        
        if total_ips <= 2:
            return [str(ip) for ip in net]
            
        # Optimization: Do not evaluate list(net.hosts()) on large subnets (like /14) to avoid crashing RAM
        if total_ips > 2000:
            chosen = set()
            attempts = 0
            needed = min(total_ips - 2, max_count)
            while len(chosen) < needed and attempts < max_count * 3:
                attempts += 1
                rand_offset = random.randint(1, total_ips - 2)
                chosen.add(str(net[rand_offset]))
            return list(chosen)
        else:
            hosts = [str(ip) for ip in net.hosts()]
            return random.sample(hosts, min(len(hosts), max_count))
    except Exception:
        return []


def run_scanner(ip_list, sni_list, mode_name, quiet=False, save_at_end=True):
    alive_ips = []
    
    # --- VISUALIZED CONCURRENT PRE-SCREENING PHASE ---
    if len(sni_list) > 1 and len(ip_list) > 1:
        if not quiet:
            print(f"{C_YELLOW}[~] Initializing engine pre-screen across {len(ip_list)} unique IPs...{RESET}")
        
        def check_single_ip(target_ip):
            if get_ping(target_ip):
                return target_ip
            return None

        total_ips = len(ip_list)
        with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as pre_executor:
            futures = [pre_executor.submit(check_single_ip, ip) for ip in ip_list]
            
            for idx, f in enumerate(as_completed(futures), 1):
                res_ip = f.result()
                if res_ip:
                    with alive_ips_lock:
                        alive_ips.append(res_ip)
                if not quiet:
                    clear_line(f" Pre-screen Progress: {idx}/{total_ips} | Responding Hosts: {len(alive_ips)} | Skipped Dead: {idx - len(alive_ips)}")
        
        if not quiet:
            print(f"\n{C_GREEN}[+] Pre-screen filtering complete. Kept {len(alive_ips)} alive targets. Filtered out {total_ips - len(alive_ips)} dead endpoints.{RESET}")
    else:
        alive_ips = list(ip_list)

    # Ensure known good baseline isn't filtered
    if MY_WORKING_IP in ip_list and MY_WORKING_IP not in alive_ips:
        alive_ips.append(MY_WORKING_IP)

    # --- MAIN SCAN MATRIX ---
    all_pairs = [(ip, sni) for ip in alive_ips for sni in sni_list]
    random.shuffle(all_pairs)
    collected = []
    
    if not all_pairs:
        if not quiet:
            print(f"{C_RED}[!] No active host targets survived pre-screening to perform matrix verification.{RESET}")
        return collected

    total_matrix_tasks = len(all_pairs)
    if not quiet:
        print(f"{C_CYAN}[~] Building check matrix: {len(alive_ips)} IPs x {len(sni_list)} SNIs = {total_matrix_tasks} Total Handshake Tasks.{RESET}")

    executor = ThreadPoolExecutor(max_workers=DEFAULT_THREADS)
    try:
        tasks = {executor.submit(analyze_protocol, p[0], p[1], mode_name): p for p in all_pairs}
        for i, future in enumerate(as_completed(tasks), 1):
            res = future.result()
            if not quiet:
                clear_line(f" Matrix Progress: {i}/{total_matrix_tasks} Checked | Matches Found: {len(collected)}")
            if res and res['status'] in ["200", "403"]:
                collected.append(res)
                if not quiet: 
                    print(f"\n {C_GREEN}[MATCH]{RESET} {res['ip']} | HTTP {res['status']} | SNI: {res['sni']} | {res['ping']}ms")
    except KeyboardInterrupt:
        print(f"\n{BOLD}{C_YELLOW}[!] Scan interrupted. Halting worker tasks cleanly...{RESET}")
        executor.shutdown(wait=False, cancel_futures=True)
        if collected and save_at_end:
            generate_final_outputs(collected, mode_name)
        raise KeyboardInterrupt

    executor.shutdown(wait=True)
    if collected and save_at_end: 
        generate_final_outputs(collected, mode_name)
    return collected


def run_blind_netlify_scan():
    print(f"\n{C_MAGENTA}=== BLIND NETLIFY EDGE SCANNER ==={RESET}")
    print(f"{C_GREEN}Starting with known working IP: {MY_WORKING_IP}{RESET}\n")
    
    level = input("Choose aggressiveness (1=Light  2=Medium  3=Heavy): ").strip() or "2"
    try:
        level = int(level)
    except ValueError:
        level = 2
    ips_per = {1: 20, 2: 50, 3: 100}.get(level, 50)
    
    ranges = load_smart_ranges()
    print(f"{C_CYAN}[Info] Loaded {len(ranges)} Netlify ranges{RESET}")
    print(f"{C_CYAN}[Info] Will test up to {ips_per} usable hosts per range{RESET}")
    
    candidate_ips = []
    for r in ranges:
        hosts = get_safe_random_hosts(r, ips_per)
        candidate_ips.extend(hosts)
    
    candidate_ips = list(set(candidate_ips))
    if MY_WORKING_IP in candidate_ips:
        candidate_ips.remove(MY_WORKING_IP)
    candidate_ips.insert(0, MY_WORKING_IP)
    
    print(f"{C_CYAN}[Info] Total unique target IPs prepared: {len(candidate_ips)}{RESET}")
    print(f"{C_CYAN}[Info] Total SNIs to process: {len(FULL_SNI_LIST)}{RESET}")
    input("\nPress Enter to execute scanning protocols...")
    
    all_results = []
    try:
        print(f"\n{C_GREEN}=== Phase 1: Testing Baseline Working Core ({MY_WORKING_IP}) ==={RESET}")
        results1 = run_scanner([MY_WORKING_IP], FULL_SNI_LIST, "BlindNetlify", quiet=False, save_at_end=False)
        all_results.extend(results1)
        
        remaining = [ip for ip in candidate_ips if ip != MY_WORKING_IP]
        print(f"\n{C_YELLOW}=== Phase 2: Scanning Remaining {len(remaining)} Global Nodes ==={RESET}")
        
        results2 = run_scanner(remaining, FULL_SNI_LIST, "BlindNetlify", quiet=False, save_at_end=False)
        all_results.extend(results2)
    except KeyboardInterrupt:
        print(f"\n{BOLD}{C_YELLOW}[!] Blind Scan sequence stopped early by request.{RESET}")
    
    print(f"\n{C_CYAN}[Info] Core Session Terminated. Total usable edge structures logged: {len(all_results)}{RESET}")
    if all_results:
        generate_final_outputs(all_results, "BlindNetlify")
    else:
        print(f"{C_RED}No clean responsive nodes found during this scan loop.{RESET}")

def troubleshooting_logic():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{BOLD}{C_YELLOW}--- DIAGNOSTIC SUITE ---{RESET}")
    print("1. Test Local Latency to Global Destinations")
    print("2. Test Current Primary Config Status")
    print("3. Check DNS Resolution Integrity")
    print("4. Back to Main Menu")
    sub_choice = input(f"\n{BOLD}Diagnostic Action > {RESET}")
    if sub_choice == '1':
        for target in ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "176.101.33.161", "2.189.1.15"]:
            p = get_ping(target)
            print(f" Target {target}: {f'{C_GREEN}{p}ms' if p else f'{C_RED}FAILED'}{RESET}")
    elif sub_choice == '2':
        for s in MY_WORKING_SNIS:
            res = analyze_protocol(MY_WORKING_IP, s, "Diagnostic")
            if res and res['status'] in ["200", "403"]: 
                print(f" {C_GREEN}[PASSED]{RESET} {s} | {res['ping']}ms")
            else: 
                print(f" {C_RED}[FAILED]{RESET} {s}")
    elif sub_choice == '3':
        for s in MY_WORKING_SNIS:
            try:
                ip = socket.gethostbyname(s)
                print(f" {s} resolves safely to {ip} {C_GREEN}[OK]{RESET}")
            except Exception: 
                print(f" {s} {C_RED}[DNS BLOCK / INTERCEPTION]{RESET}")
    input("\nPress Enter to return to engine panel...")

def main_menu():
    while True:
        try:
            NETLIFY_RANGES = load_smart_ranges()
            os.system('cls' if os.name == 'nt' else 'clear')
            
            print(f"{BOLD}{C_GREEN}╔═════════════════════════════════════════════════════════════════════╗")
            print(f"║           NETLIFY STEALTH SCANNER v1.5 By JeetHm && G               ║")
            print(f"╚═════════════════════════════════════════════════════════════════════╝{RESET}")
            print(f" Primary SNIs: {', '.join(MY_WORKING_SNIS)}")
            print(f" Storage Path: ./{RESULTS_DIR}/")
            print("-" * 50)
            print("1. Fast Scan (ips.txt x Primary SNIs)")
            print("2. Deep Matrix (ips.txt x FULL sni.txt)")
            print("3. Smart Subnet Scan (Learned Ranges + Working IP)")
            print("4. Turbo Mode (Infinite Isolated Loop Scanner)")
            print("5. Blind Netlify Expansion Scan")
            print("6. Test Diagnostics")
            print("7. Help & Troubleshooting")
            print("0. Exit")
            print("-" * 50)
            choice = input(f"{BOLD}Select Action > {RESET}").strip()
            
            if choice == '1':
                try: run_scanner(FULL_IP_LIST, MY_WORKING_SNIS, "FastScan")
                except KeyboardInterrupt: pass
                input("\nDone. Press Enter...")
            elif choice == '2':
                try: run_scanner(FULL_IP_LIST, FULL_SNI_LIST, "DeepScan")
                except KeyboardInterrupt: pass
                input("\nDone. Press Enter...")
            elif choice == '3':
                try:
                    limit = int(input("IPs per subnet (Default 30): ") or "30")
                except ValueError:
                    limit = 30
                auto = [MY_WORKING_IP]
                for r in NETLIFY_RANGES:
                    hosts = get_safe_random_hosts(r, limit)
                    auto.extend(hosts)
                try: run_scanner(list(set(auto)), MY_WORKING_SNIS, "SmartScan")
                except KeyboardInterrupt: pass
                input("\nDone. Press Enter...")
            elif choice == '4':
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"{BOLD}{C_MAGENTA}--- TURBO MODE ACTIVE (Ctrl+C to stop & save) ---{RESET}\n")
                turbo_collected = []
                seen = set()
                total_tested_pairs = 0
                
                with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
                    try:
                        while True:
                            target_range = random.choice(load_smart_ranges())
                            test_ips = get_safe_random_hosts(target_range, 10)
                            
                            if not test_ips:
                                continue
                                
                            if random.random() < 0.1: 
                                test_ips.append(MY_WORKING_IP)
                                
                            all_pairs = [(ip, sni) for ip in test_ips for sni in MY_WORKING_SNIS]
                            random.shuffle(all_pairs)
                            
                            tasks = {executor.submit(analyze_protocol, p[0], p[1], "TurboScan"): p for p in all_pairs}
                            for future in as_completed(tasks):
                                res = future.result()
                                total_tested_pairs += 1
                                
                                if res and res['status'] in ["200", "403"]:
                                    key = (res['ip'], res['sni'])
                                    if key not in seen:
                                        seen.add(key)
                                        turbo_collected.append(res)
                                        print(f"\n{C_GREEN}[+] MATCH | {res['ip']} | {res['sni']} | {res['ping']}ms{RESET}")
                                
                                clear_line(f"{BOLD}{C_CYAN}[Checked: {total_tested_pairs} | Matches: {len(turbo_collected)}] Press CTRL+C to Save & Exit{RESET}")
                            time.sleep(0.3)
                    except KeyboardInterrupt:
                        print("")
                        print(f"\n{BOLD}{C_YELLOW}[!] Turbo Mode Interrupted. Launching export manager...{RESET}")
                        if turbo_collected:
                            generate_final_outputs(turbo_collected, "TurboScan")
                        input("\nPress Enter to return to operational window...")
            elif choice == '5':
                run_blind_netlify_scan()
                input("\nBlind Scan finished. Press Enter...")
            elif choice == '6':
                troubleshooting_logic()
            elif choice == '7':
                print(f"\n{BOLD}{C_YELLOW}Help & Troubleshooting Documentation:{RESET}")
                print(" - Finding IPs depends entirely on how heavily filtered your domestic ISP context is.")
                print(" - When things drop heavily, subnets and IP routes rotate or are gradually unwhitelisted via specific SNIs.")
                print(" - Status 200: Perfect match. Ideal structure for VLESS configurations.")
                print(" - Status 403: Safe baseline connection. Edge established but content verification blocked.")
                print(" - Status ??? / TIMEOUT: Local Deep Packet Inspection (DPI) dropped or dropped the TLS handshake packets.")
                print(" - Matrix Logic: Comprehensive pairing matrix where every IP element runs against all loaded SNIs.")
                print(" - Dashboard: Output compiles into cleanly responsive layout grids saved within the local directories.")
                input("\nPress Enter...")
            elif choice == '0':
                print(f"{C_GREEN}Goodbye!{RESET}")
                sys.exit()
        except KeyboardInterrupt:
            print(f"\n{C_YELLOW}[!] Core menu caught interrupt. Choose '0' to exit cleanly.{RESET}")
            time.sleep(1)


if __name__ == "__main__":
    main_menu()