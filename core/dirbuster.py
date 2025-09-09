#!/usr/bin/env python3
import sys
import requests
import datetime
import os
import time
import argparse
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

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

def print_banner(base_url, wordlist_path, extensions_used, total_words, threads):
    """Ispisuje banner u gobuster stilu"""
    print("=" * 70)
    print("DirBuster v2.0 - Threaded Edition")
    print("by A13k5a M1l1c3v")
    print("=" * 70)
    print(f"[+] Url:                     {base_url}")
    print(f"[+] Method:                  GET")
    print(f"[+] Threads:                 {threads}")
    print(f"[+] Wordlist:                {wordlist_path}")
    print(f"[+] Negative Status codes:   404")
    print(f"[+] User Agent:              DirBuster/2.0")
    if extensions_used:
        print(f"[+] Extensions:              {', '.join(EXTENSIONS[1:])}")  # Skip empty extension
    print(f"[+] Timeout:                 10s")
    print("=" * 70)
    print("Starting DirBuster in directory enumeration mode")
    print("=" * 70)

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
                    for path, code, size, redirect in found_paths:
                        if code == 403:
                            continue  # preskoči 403
                        # Format: http://ip_adresa:port/resurs
                        full_url = urljoin(base_url, path)
                        f.write(f"{full_url}\n")
                else:
                    # Ako nema rezultata, fajl može biti prazan
                    pass
    except Exception as e:
        with print_lock:
            print(f"{Fore.RED}[!] Error saving machine readable results: {e}{Style.RESET_ALL}")




def save_report(target_url, found_paths, scan_stats):
    """Čuva detaljan izveštaj u reports folder"""
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    
    timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    filename = os.path.join(REPORTS_DIR, f"dirb_{timestamp}.txt")
    
    with open(filename, "w", encoding='utf-8') as f:
        f.write(f"DirBuster Scan Results\n")
        f.write("=" * 70 + "\n")
        f.write(f"Target URL: {target_url}\n")
        f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Requests: {scan_stats['total_requests']}\n")
        f.write(f"Found Paths: {len(found_paths)}\n")
        f.write(f"Scan Duration: {scan_stats['duration']:.2f} seconds\n")
        f.write(f"Requests/second: {scan_stats['requests_per_second']:.2f}\n")
        f.write("\n" + "=" * 70 + "\n\n")
        
        if found_paths:
            f.write("DISCOVERED PATHS:\n")
            f.write("-" * 30 + "\n")
            for path, code, size, redirect in found_paths:
                if redirect:
                    f.write(f"/{path:<30} (Status: {code}) [Size: {size}]\n")
                else:
                    f.write(f"/{path:<30} (Status: {code}) [Size: {size}]\n")
        else:
            f.write("No interesting directories/files found.\n")
    
    with print_lock:
        print("=" * 70)
        print("Finished")
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
            return (word, status_code, content_length, redirect_location)
    except requests.RequestException:
        pass
    return None

stop_progress = threading.Event()

def dirbuster_scan(base_url, wordlist, delay=0, threads=10):
    found = []
    total = len(wordlist)
    completed = 0
    start_time = time.time()

    def create_session():
        session = requests.Session()
        session.headers.update({"User-Agent": "DirBuster/2.0"})
        adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def progress_printer():
        while not stop_progress.is_set():
            with print_lock:
                percent = (completed / total) * 100
                print(f"\rProgress: {completed} / {total} ({percent:.2f}%)", end="", flush=True)
            time.sleep(0.2)

    progress_thread = threading.Thread(target=progress_printer)
    progress_thread.start()

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
                        word, status_code, size, redirect = result
                        found.append((word, status_code, size, redirect))

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
                            print("\r" + " " * 80 + "\r", end="", flush=True)
                            print(f"{color}[+] /{word:<15} (Status: {status_code}) [Size: {size}]{Style.RESET_ALL}")
                except Exception:
                    pass

    except KeyboardInterrupt:
        with print_lock:
            print(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")

    finally:
        stop_progress.set()
        progress_thread.join()

        with print_lock:
            print(f"\rProgress: {completed} / {total} (100.00%)")

    end_time = time.time()
    duration = end_time - start_time
    rps = completed / duration if duration > 0 else 0

    scan_stats = {
        'total_requests': completed,
        'duration': duration,
        'start_time': start_time,
        'end_time': end_time,
        'requests_per_second': rps
    }

    return found, scan_stats




def main():
    # Dodatne funkcije ukoliko budem imao volje da proširujem alat
    parser = argparse.ArgumentParser(description='DirBuster - Directory Enumeration Tool (Threaded)')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', default='80', help='Target port (default: 80)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist path')
    parser.add_argument('-e', '--extensions', action='store_true', help='Use file extensions')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests in seconds')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--https', action='store_true', help='Use HTTPS instead of HTTP')
    parser.add_argument('--path', default='', help='Base path to start enumeration from')
    
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
        threads = 20  # Default broj threadova
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
    
    # Validacija broja threadova
    if threads < 1:
        threads = 1
    elif threads > 50:
        print(f"{Fore.YELLOW}[!] Warning: Using {threads} threads might be too aggressive. Consider reducing to 20-30.{Style.RESET_ALL}")
    
    # Test konekcije
    if not test_connection(base_url):
        sys.exit(1)
    
    # Učitaj wordlist
    wordlist = load_wordlist(wordlist_path)
    
    # Proširi sa ekstenzijama ako je potrebno
    if extensions_used:
        wordlist = expand_wordlist(wordlist, True)
    
    # Prikaži banner
    print_banner(base_url, wordlist_path, extensions_used, len(wordlist), threads)
    
    # Pokreni skeniranje
    found_paths, scan_stats = dirbuster_scan(base_url, wordlist, delay, threads)
    
    end_time = time.time()
    scan_stats["end_time"] = end_time
    duration = end_time - scan_stats["start_time"]

    if duration > 0:
        scan_stats["requests_per_second"] = scan_stats["total_requests"] / duration
    else:
        scan_stats["requests_per_second"] = 0

    # Sačuvaj oba tipa rezultata
    save_report(base_url, found_paths, scan_stats)
    save_machine_readable_results(base_url, found_paths)

if __name__ == "__main__":
    main()