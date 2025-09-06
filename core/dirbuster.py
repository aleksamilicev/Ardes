#!/usr/bin/env python3
import sys
import requests
import datetime
import os
import time
import argparse
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

# Inicijalizacija colorama
init(autoreset=True)

# Putevi relativni na lokaciju fajla
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST = os.path.join(BASE_DIR, "..", "data", "common-dirb.txt")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Status kodovi koji se smatraju "interesantnim"
INTERESTING_CODES = [200, 201, 202, 204, 301, 302, 307, 401, 403, 500, 503]

# Ekstenzije za dodatno testiranje
EXTENSIONS = ['', '.html', '.php', '.asp', '.aspx', '.jsp', '.txt', '.bak', '.old']

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
        return f"{size_bytes/1024:.0f}"
    else:
        return f"{size_bytes/(1024*1024):.0f}"

def test_connection(base_url):
    """Testira konekciju sa target serverom"""
    try:
        response = requests.get(base_url, timeout=5)
        return True
    except requests.RequestException:
        print(f"[!] Unable to connect to {base_url}")
        return False

def print_banner(base_url, wordlist_path, extensions_used, total_words):
    """Ispisuje banner u gobuster stilu"""
    print("=" * 63)
    print("DirBuster v2.0")
    print("by A13k5a M1l1c3v")
    print("=" * 63)
    print(f"[+] Url:                     {base_url}")
    print(f"[+] Method:                  GET")
    print(f"[+] Wordlist:                {wordlist_path}")
    print(f"[+] Negative Status codes:   404")
    print(f"[+] User Agent:              DirBuster/2.0")
    if extensions_used:
        print(f"[+] Extensions:              {', '.join(EXTENSIONS[1:])}")  # Skip empty extension
    print(f"[+] Timeout:                 5s")
    print("=" * 63)
    print("Starting DirBuster in directory enumeration mode")
    print("=" * 63)

def save_report(target_url, found_paths, scan_stats):
    """Čuva detaljan izveštaj"""
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    
    timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    filename = os.path.join(REPORTS_DIR, f"dirb_{timestamp}.txt")
    
    with open(filename, "w", encoding='utf-8') as f:
        f.write(f"DirBuster Scan Results\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target URL: {target_url}\n")
        f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Requests: {scan_stats['total_requests']}\n")
        f.write(f"Found Paths: {len(found_paths)}\n")
        f.write(f"Scan Duration: {scan_stats['duration']:.2f} seconds\n")
        f.write("\n" + "=" * 60 + "\n\n")
        
        if found_paths:
            f.write("DISCOVERED PATHS:\n")
            f.write("-" * 30 + "\n")
            for path, code, size, redirect in found_paths:
                if redirect:
                    f.write(f"/{path:<30} (Status: {code}) [Size: {size}] [--> {redirect}]\n")
                else:
                    f.write(f"/{path:<30} (Status: {code}) [Size: {size}]\n")
        else:
            f.write("No interesting directories/files found.\n")
    
    print(f"{Fore.GREEN}[+] Report saved: {filename}{Style.RESET_ALL}")

def dirbuster_scan(base_url, wordlist, delay=0):
    """Glavna funkcija za skeniranje direktorijuma - gobuster stil"""
    found = []
    total = len(wordlist)
    start_time = time.time()
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'DirBuster/2.0'
    })
    
    try:
        for i, word in enumerate(wordlist, start=1):
            url = urljoin(base_url, word)
            
            try:
                response = session.get(url, timeout=5, allow_redirects=False)
                status_code = response.status_code
                content_length = len(response.content)
                
                if status_code in INTERESTING_CODES:
                    # Odredi boju na osnovu status koda
                    if status_code == 200:
                        color = Fore.GREEN
                    elif status_code == 301:
                        color = Fore.CYAN
                    else:
                        color = Fore.GREEN  # default
                    
                    # Obriši progress liniju pre ispisa rezultata
                    print(f"\r{' ' * 60}\r", end="", flush=True)
                    
                    redirect_location = response.headers.get('Location', '')
                    
                    # Format output kao gobuster
                    if redirect_location:
                        print(f"{color}[+] /{word:<15} (Status: {status_code}) "
                              f"[Size: {format_size(content_length)}] [--> {redirect_location}]{Style.RESET_ALL}")
                        found.append((word, status_code, format_size(content_length), redirect_location))
                    else:
                        print(f"{color}[+] /{word:<15} (Status: {status_code}) "
                              f"[Size: {format_size(content_length)}]{Style.RESET_ALL}")
                        found.append((word, status_code, format_size(content_length), None))
                
                # Progress update na istoj liniji (kao gobuster)
                progress_percent = (i / total) * 100
                print(f"\rProgress: {i} / {total} ({progress_percent:.2f}%)", end="", flush=True)
                
                if delay > 0:
                    time.sleep(delay)
                    
            except requests.RequestException:
                # I dalje update-uj progress čak i za neuspešne zahteve
                progress_percent = (i / total) * 100
                print(f"\rProgress: {i} / {total} ({progress_percent:.2f}%)", end="", flush=True)
                continue
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
    
    # Final progress - obriši prethodnu liniju i ispiši finalnu
    print(f"\rProgress: {i} / {total} (100.00%)")
    
    end_time = time.time()
    duration = end_time - start_time
    
    print("=" * 63)
    print("Finished")
    print("=" * 63)
    
    scan_stats = {
        'total_requests': i,
        'duration': duration
    }
    
    return found, scan_stats


def main():
    # Dodatne funkcije ukoliko budem imao volje da proširujem alat
    parser = argparse.ArgumentParser(description='DirBuster - Directory Enumeration Tool')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', default='80', help='Target port (default: 80)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist path')
    parser.add_argument('-e', '--extensions', action='store_true', help='Use file extensions')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests in seconds')
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
    
    # Test konekcije
    if not test_connection(base_url):
        sys.exit(1)
    
    # Učitaj wordlist
    wordlist = load_wordlist(wordlist_path)
    
    # Proširi sa ekstenzijama ako je potrebno
    if extensions_used:
        wordlist = expand_wordlist(wordlist, True)
    
    # Prikaži banner
    print_banner(base_url, wordlist_path, extensions_used, len(wordlist))
    
    # Pokreni skeniranje
    found_paths, scan_stats = dirbuster_scan(base_url, wordlist, delay)
    
    # Sačuvaj izveštaj
    save_report(base_url, found_paths, scan_stats)

if __name__ == "__main__":
    main()