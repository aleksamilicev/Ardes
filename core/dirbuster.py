#!/usr/bin/env python3
import sys
import requests
import datetime
import os
import time
import argparse
from urllib.parse import urljoin, urlparse, urlunparse
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from queue import Queue

# Inicijalizacija colorama
init(autoreset=True)

# Putevi relativni na lokaciju fajla
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST = os.path.join(BASE_DIR, "..", "data", "common-dirb.txt")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
RESULTS_DIR = os.path.join(BASE_DIR, "results")  # Novi folder za mašinski čitljive rezultate

# Status kodovi koji se smatraju "interesantnim"
INTERESTING_CODES = [200, 201, 202, 204, 301, 302, 307, 401, 403, 500, 503]

# Ekstenzije za dodatno testiranje
EXTENSIONS = ['', '.html', '.php', '.asp', '.aspx', '.jsp', '.txt', '.bak', '.old']

# Thread-safe lock za ispis i čuvanje rezultata
print_lock = threading.Lock()
results_lock = threading.Lock()
scanned_paths_lock = threading.Lock()

# Globalni set za praćenje već skeniranih putanja (da se izbegnu duplikati)
scanned_paths = set()
all_found_paths = []

def load_wordlist(wordlist_path=None):
    """Učitavanje wordlist-e"""
    path = wordlist_path if wordlist_path else WORDLIST
    
    if not os.path.exists(path):
        print(f"[!] Wordlist not found: {path}")
        sys.exit(1)
    
    try:
        with open(path, "r", encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return words
    except Exception as e:
        print(f"[!] Error loading wordlist: {e}")
        sys.exit(1)

def expand_wordlist(words, use_extensions=False):
    """Proširuje wordlist sa ekstenzijama"""
    if not use_extensions:
        return words
    
    expanded = []
    for word in words:
        for ext in EXTENSIONS:
            expanded.append(f"{word}{ext}")
    
    return expanded

def format_size(size_bytes):
    """Formatira veličinu fajla"""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.0f}K"
    else:
        return f"{size_bytes/(1024*1024):.0f}M"

def test_connection(base_url):
    """Testira konekciju sa target serverom"""
    try:
        response = requests.get(base_url, timeout=10)
        return True
    except requests.RequestException:
        print(f"[!] Unable to connect to {base_url}")
        return False

def ask_yes_no(question):
    """Pita korisnika za Yes/No odgovor"""
    while True:
        answer = input(f"{Fore.CYAN}{question} [Y/n]: {Style.RESET_ALL}").strip().lower()
        if answer in ['y', 'yes', '']:
            return True
        elif answer in ['n', 'no']:
            return False
        else:
            print(f"{Fore.RED}Invalid input. Please enter Y or N.{Style.RESET_ALL}")

def ask_depth():
    """Pita korisnika za željenu dubinu rekurzije"""
    while True:
        try:
            depth = input(f"{Fore.CYAN}Enter maximum recursion depth (1-10): {Style.RESET_ALL}").strip()
            depth = int(depth)
            if 1 <= depth <= 10:
                return depth
            else:
                print(f"{Fore.RED}Please enter a number between 1 and 10.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")

def print_banner(base_url, wordlist_path, extensions_used, total_words, threads, max_depth, recursive):
    """Ispisuje banner u gobuster stilu"""
    print("=" * 70)
    if recursive:
        print("DirBuster v2.0 - Recursive Threaded Edition")
    else:
        print("DirBuster v2.0 - Simple Mode (No Recursion)")
    print("by A13k5a M1l1c3v")
    print("=" * 70)
    print(f"[+] Url:                     {base_url}")
    print(f"[+] Method:                  GET")
    print(f"[+] Threads:                 {threads}")
    print(f"[+] Wordlist:                {wordlist_path}")
    if recursive:
        print(f"[+] Recursive Depth:         {max_depth}")
    else:
        print(f"[+] Recursive:               Disabled")
    print(f"[+] Negative Status codes:   404")
    print(f"[+] User Agent:              DirBuster/2.0")
    if extensions_used:
        print(f"[+] Extensions:              {', '.join(EXTENSIONS[1:])}")  # Skip empty extension
    print(f"[+] Timeout:                 10s")
    print("=" * 70)
    if recursive:
        print("Starting Recursive DirBuster in directory enumeration mode")
    else:
        print("Starting DirBuster in simple enumeration mode")
    print("=" * 70)

def normalize_path(path):
    """Normalizuje putanju za konzistentnost"""
    if not path.startswith('/'):
        path = '/' + path
    if not path.endswith('/') and '.' not in os.path.basename(path):
        path = path + '/'
    return path

def is_directory(path, status_code, content_length, response_headers=None):
    """Određuje da li je putanja direktorijum na osnovu različitih faktora"""
    # Ako je 301 (redirect), vrlo verovatno je direktorijum
    if status_code == 301:
        return True
    
    # Ako putanja završava sa '/', verovatno je direktorijum
    if path.endswith('/'):
        return True
    
    # Ako nema ekstenziju i status je 200, može biti direktorijum
    if status_code == 200 and '.' not in os.path.basename(path):
        return True
    
    # Ako je sadržaj vrlo mali (< 1KB) i nema ekstenziju, može biti prazan direktorijum
    if status_code == 200 and content_length < 1024 and '.' not in os.path.basename(path):
        return True
    
    return False

def save_machine_readable_results(target_url, found_paths):
    """Čuva rezultate u mašinski čitljivom formatu u results/dirb.txt, bez 403"""
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    
    filename = os.path.join(RESULTS_DIR, "dirb.txt")
    
    # Parse base URL da dobiješ osnovni URL
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    try:
        with results_lock:  # Thread-safe pisanje u fajl
            with open(filename, "w", encoding='utf-8') as f:
                if found_paths:
                    for path, code, size, redirect, depth in found_paths:
                        if code == 403:
                            continue  # preskoči 403
                        
                        # Ako postoji redirect (status 301), koristi redirect URL bez trailing slash-a
                        if redirect and code == 301:
                            # Redirect URL već ima pun path, samo ukloni trailing slash
                            full_url = redirect.rstrip('/')
                        else:
                            # Za ostale slučajeve (200, itd.), konstruiši URL
                            full_url = urljoin(base_url, path)
                        
                        f.write(f"{full_url}\n")
                else:
                    # Ako nema rezultata, fajl može biti prazan
                    pass
    except Exception as e:
        with print_lock:
            print(f"{Fore.RED}[!] Error saving machine readable results: {e}{Style.RESET_ALL}")

def save_report(target_url, found_paths, scan_stats, recursive):
    """Čuva detaljan izveštaj u reports folder"""
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    
    timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    if recursive:
        filename = os.path.join(REPORTS_DIR, f"dirb_recursive_{timestamp}.txt")
    else:
        filename = os.path.join(REPORTS_DIR, f"dirb_simple_{timestamp}.txt")
    
    with open(filename, "w", encoding='utf-8') as f:
        if recursive:
            f.write(f"DirBuster Recursive Scan Results\n")
        else:
            f.write(f"DirBuster Simple Scan Results\n")
        f.write("=" * 70 + "\n")
        f.write(f"Target URL: {target_url}\n")
        f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Requests: {scan_stats['total_requests']}\n")
        f.write(f"Found Paths: {len(found_paths)}\n")
        f.write(f"Scan Duration: {scan_stats['duration']:.2f} seconds\n")
        f.write(f"Requests/second: {scan_stats['requests_per_second']:.2f}\n")
        if recursive:
            f.write(f"Max Recursion Depth: {scan_stats.get('max_depth', 'N/A')}\n")
        f.write("\n" + "=" * 70 + "\n\n")
        
        if found_paths:
            if recursive:
                f.write("DISCOVERED PATHS (by depth):\n")
                f.write("-" * 40 + "\n")
                
                # Grupiši po dubini
                paths_by_depth = {}
                for path, code, size, redirect, depth in found_paths:
                    if depth not in paths_by_depth:
                        paths_by_depth[depth] = []
                    paths_by_depth[depth].append((path, code, size, redirect))
                
                for depth in sorted(paths_by_depth.keys()):
                    f.write(f"\nDEPTH {depth}:\n")
                    f.write("-" * 20 + "\n")
                    for path, code, size, redirect in paths_by_depth[depth]:
                        indent = "  " * depth
                        if redirect:
                            f.write(f"{indent}/{path:<30} (Status: {code}) [Size: {size}] -> {redirect}\n")
                        else:
                            f.write(f"{indent}/{path:<30} (Status: {code}) [Size: {size}]\n")
            else:
                f.write("DISCOVERED PATHS:\n")
                f.write("-" * 40 + "\n")
                for path, code, size, redirect, depth in found_paths:
                    if redirect:
                        f.write(f"/{path:<30} (Status: {code}) [Size: {size}] -> {redirect}\n")
                    else:
                        f.write(f"/{path:<30} (Status: {code}) [Size: {size}]\n")
        else:
            f.write("No interesting directories/files found.\n")
    
    with print_lock:
        print("=" * 70)
        if recursive:
            print("Recursive scan finished")
        else:
            print("Simple scan finished")
        print("=" * 70)
        print(f"{Fore.GREEN}[+] Report saved: {filename}{Style.RESET_ALL}")

def test_single_path(session, base_url, word, delay=0):
    """Testira jednu putanju - bez printanja"""
    url = urljoin(base_url, word)
    try:
        response = session.get(url, timeout=10, allow_redirects=False)
        status_code = response.status_code
        content_length = len(response.content)

        if status_code in [200, 301, 403]:
            redirect_location = response.headers.get("Location", "")
            return (word, status_code, content_length, redirect_location, response.headers)
    except requests.RequestException:
        pass
    return None

def dirbuster_scan_single_level(base_url, wordlist, delay=0, threads=10, depth=0):
    """Skenira jedan nivo direktorijuma"""
    found = []
    total = len(wordlist)
    completed = 0
    
    depth_start_time = time.time()  # Vreme početka skeniranja ovog depth-a
    
    def create_session():
        session = requests.Session()
        session.headers.update({"User-Agent": "DirBuster/2.0"})
        adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_word = {
                executor.submit(test_single_path, create_session(), base_url, word, delay): word
                for word in wordlist
            }

            for future in as_completed(future_to_word):
                completed += 1
                try:
                    result = future.result()
                    if result:
                        word, status_code, size, redirect, headers = result
                        found.append((word, status_code, size, redirect, depth, headers))

                        # Boje po status kodu
                        if status_code == 200:
                            color = Fore.GREEN
                        elif status_code == 301:
                            color = Fore.CYAN
                        elif status_code == 403:
                            color = Fore.YELLOW
                        else:
                            color = Fore.WHITE

                        with print_lock:
                            indent = "  " * depth
                            depth_indicator = f"[D{depth}]" if depth > 0 else ""
                            if redirect:
                                print(f"{color}{depth_indicator}{indent}[+] /{word:<15} (Status: {status_code}) [Size: {size}] -> {redirect}{Style.RESET_ALL}")
                            else:
                                print(f"{color}{depth_indicator}{indent}[+] /{word:<15} (Status: {status_code}) [Size: {size}]{Style.RESET_ALL}")
                except Exception:
                    pass

    except KeyboardInterrupt:
        with print_lock:
            print(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
        raise

    # Vreme potrebno za ovaj depth
    depth_end_time = time.time()
    depth_duration = depth_end_time - depth_start_time
    
    with print_lock:
        print(f"{Fore.MAGENTA}[*] Depth {depth} scan completed in {depth_duration:.2f} seconds{Style.RESET_ALL}")

    return found, completed

def recursive_dirbuster_scan(base_url, wordlist, delay=0, threads=10, max_depth=1):
    """Glavna rekurzivna funkcija za skeniranje"""
    global scanned_paths, all_found_paths
    
    total_requests = 0
    start_time = time.time()
    
    # Queue za direktorijume koji treba da se skeniraju
    dirs_to_scan = Queue()
    dirs_to_scan.put((base_url, 0))  # (URL, dubina)
    
    try:
        while not dirs_to_scan.empty():
            current_url, current_depth = dirs_to_scan.get()
            
            # Proveri da li je već skeniran ovaj path
            with scanned_paths_lock:
                if current_url in scanned_paths:
                    continue
                scanned_paths.add(current_url)
            
            # Prekini ako smo dostigli maksimalnu dubinu
            if current_depth > max_depth:
                continue
            
            with print_lock:
                if current_depth > 0:
                    print(f"\n{Fore.MAGENTA}[*] Scanning depth {current_depth}: {current_url}{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.MAGENTA}[*] Starting initial scan: {current_url}{Style.RESET_ALL}")
            
            # Skeniraj trenutni nivo
            found, requests_made = dirbuster_scan_single_level(
                current_url, wordlist, delay, threads, current_depth
            )
            
            total_requests += requests_made
            
            # Dodaj pronađene putanje u globalni rezultat
            with results_lock:
                all_found_paths.extend(found)
            
            # Pronađi direktorijume za dalje skeniranje
            if current_depth < max_depth:
                for word, status_code, size, redirect, depth, headers in found:
                    # Skeniraj samo 200 i 301 status kodove
                    if status_code in [200, 301]:
                        # Determinišemo da li je direktorijum
                        if is_directory(word, status_code, size, headers):
                            new_path = normalize_path(word)
                            # Ispravka: konstruiši URL pravilno
                            if not current_url.endswith('/'):
                                new_url = current_url + '/' + new_path.lstrip('/')
                            else:
                                new_url = current_url + new_path.lstrip('/')
                            
                            # Dodaj u queue za skeniranje
                            dirs_to_scan.put((new_url, current_depth + 1))
                            
                            with print_lock:
                                print(f"{Fore.BLUE}[*] Added to scan queue: {new_url} (depth {current_depth + 1}){Style.RESET_ALL}")

    except KeyboardInterrupt:
        with print_lock:
            print(f"\n{Fore.RED}[!] Recursive scan interrupted by user.{Style.RESET_ALL}")

    end_time = time.time()
    duration = end_time - start_time
    rps = total_requests / duration if duration > 0 else 0

    scan_stats = {
        'total_requests': total_requests,
        'duration': duration,
        'start_time': start_time,
        'end_time': end_time,
        'requests_per_second': rps,
        'max_depth': max_depth
    }

    return all_found_paths, scan_stats

def simple_dirbuster_scan(base_url, wordlist, delay=0, threads=10):
    """Jednostavno skeniranje bez rekurzije (kao gobuster)"""
    global all_found_paths
    
    total_requests = 0
    start_time = time.time()
    
    print(f"\n{Fore.MAGENTA}[*] Starting simple scan: {base_url}{Style.RESET_ALL}")
    
    # Skeniraj samo base URL
    found, requests_made = dirbuster_scan_single_level(
        base_url, wordlist, delay, threads, 0
    )
    
    total_requests = requests_made
    
    # Konvertuj rezultate u konzistentan format
    formatted_found = []
    for word, status_code, size, redirect, depth, headers in found:
        formatted_found.append((word, status_code, size, redirect, depth))
    
    end_time = time.time()
    duration = end_time - start_time
    rps = total_requests / duration if duration > 0 else 0

    scan_stats = {
        'total_requests': total_requests,
        'duration': duration,
        'start_time': start_time,
        'end_time': end_time,
        'requests_per_second': rps
    }

    return formatted_found, scan_stats

def main():
    global scanned_paths, all_found_paths
    
    # Reset globalnih varijabli
    scanned_paths = set()
    all_found_paths = []
    
    parser = argparse.ArgumentParser(description='DirBuster - Directory Enumeration Tool')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', default='80', help='Target port (default: 80)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist path')
    parser.add_argument('-e', '--extensions', action='store_true', help='Use file extensions')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests in seconds')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--https', action='store_true', help='Use HTTPS instead of HTTP')
    parser.add_argument('--path', default='', help='Base path to start enumeration from')
    parser.add_argument('--non-interactive', action='store_true', help='Skip interactive prompts (use defaults)')
    parser.add_argument('-r', '--recursive', action='store_true', help='Enable recursive scanning (non-interactive)')
    parser.add_argument('--max-depth', type=int, default=3, help='Maximum recursion depth (default: 3, for non-interactive mode)')
    
    # Fallback na stari način ako nema argparse argumenata
    if len(sys.argv) == 2 or (len(sys.argv) == 3 and sys.argv[2].isdigit()):
        # Stari format: python3 dirbuster.py IP [port]
        target_ip = sys.argv[1]
        port = sys.argv[2] if len(sys.argv) == 3 else "80"
        protocol = 'http'
        base_url = f"{protocol}://{target_ip}:{port}"
        wordlist_path = WORDLIST
        extensions_used = False
        delay = 0
        threads = 40  # Default broj threadova
        
        # Pitaj korisnika za rekurziju i depth
        use_recursion = ask_yes_no("Do you want to perform recursive scanning?")
        if use_recursion:
            max_depth = ask_depth()
        else:
            max_depth = 0
    else:
        args = parser.parse_args()
        
        # Konstruiši URL
        protocol = 'https' if args.https else 'http'
        base_url = f"{protocol}://{args.target}:{args.port}"
        
        if args.path:
            base_url = urljoin(base_url, args.path)
        
        wordlist_path = args.wordlist if args.wordlist else WORDLIST
        extensions_used = args.extensions
        delay = args.delay
        threads = args.threads
        
        # Interaktivni ili non-interaktivni mod
        if args.non_interactive:
            use_recursion = args.recursive
            max_depth = args.max_depth if use_recursion else 0
        else:
            # Pitaj korisnika
            use_recursion = ask_yes_no("Do you want to perform recursive scanning?")
            if use_recursion:
                max_depth = ask_depth()
            else:
                max_depth = 0
    
    # Validacija parametara
    if threads < 1:
        threads = 1
    elif threads > 50:
        print(f"{Fore.YELLOW}[!] Warning: Using {threads} threads might be too aggressive. Consider reducing to 20-30.{Style.RESET_ALL}")
    
    if use_recursion and max_depth < 1:
        max_depth = 1
    elif use_recursion and max_depth > 10:
        print(f"{Fore.YELLOW}[!] Warning: Max depth {max_depth} might be too deep and slow. Consider reducing to 3-5.{Style.RESET_ALL}")
    
    # Test konekcije
    if not test_connection(base_url):
        sys.exit(1)
    
    # Učitaj wordlist
    wordlist = load_wordlist(wordlist_path)
    
    # Proširi sa ekstenzijama ako je potrebno
    if extensions_used:
        wordlist = expand_wordlist(wordlist, True)
    
    # Prikaži banner
    print_banner(base_url, wordlist_path, extensions_used, len(wordlist), threads, max_depth, use_recursion)
    
    # Pokreni skeniranje (rekurzivno ili jednostavno)
    if use_recursion:
        found_paths, scan_stats = recursive_dirbuster_scan(base_url, wordlist, delay, threads, max_depth)
        # Konvertuj format rezultata za kompatibilnost sa postojećim funkcijama
        formatted_paths = []
        for path, code, size, redirect, depth, headers in found_paths:
            formatted_paths.append((path, code, size, redirect, depth))
    else:
        formatted_paths, scan_stats = simple_dirbuster_scan(base_url, wordlist, delay, threads)
    
    # Sačuvaj oba tipa rezultata
    save_report(base_url, formatted_paths, scan_stats, use_recursion)
    save_machine_readable_results(base_url, formatted_paths)
    
    # Finalni prikaz statistika
    with print_lock:
        if use_recursion:
            print(f"\n{Fore.GREEN}[+] Recursive scan completed!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+] Simple scan completed!{Style.RESET_ALL}")
        print(f"[+] Total paths found: {len(formatted_paths)}")
        print(f"[+] Total requests made: {scan_stats['total_requests']}")
        print(f"[+] Scan duration: {scan_stats['duration']:.2f} seconds")
        print(f"[+] Average requests/second: {scan_stats['requests_per_second']:.2f}")

if __name__ == "__main__":
    main()