#!/usr/bin/env python3
import os
import sys
import re
import datetime
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from urllib.parse import urlparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Init colorama
init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DIRB_FILE = os.path.join(RESULTS_DIR, "dirb.txt")
FETCH_FILE = os.path.join(RESULTS_DIR, "fetch.txt")
KEYWORDS_FILE = os.path.join(BASE_DIR, "../data/fingerprint_keywords.txt")

# Keywords koje fingerprint.py može da koristi za prepoznavanje tehnologija
FINGERPRINT_KEYWORDS = [
    # Web serveri
    'apache', 'nginx', 'iis', 'lighttpd', 'tomcat', 'jetty',
    # Programski jezici
    'php', 'python', 'java', 'asp', 'jsp', 'perl', 'ruby', 'node.js',
    # CMS sistemi
    'wordpress', 'drupal', 'joomla', 'magento', 'prestashop', 'opencart',
    # Frameworks
    'laravel', 'symfony', 'codeigniter', 'zend', 'cakephp', 'yii',
    'django', 'flask', 'spring', 'struts', 'hibernate',
    # Baze podataka
    'mysql', 'postgresql', 'oracle', 'mssql', 'mongodb', 'sqlite',
    # JavaScript frameworks/libraries
    'jquery', 'angular', 'react', 'vue', 'bootstrap', 'foundation',
    # Version info patterns
    'version', 'ver', 'build', 'release',
    # Admin panels
    'admin', 'administrator', 'panel', 'dashboard', 'login',
    # Security headers
    'x-powered-by', 'server', 'x-generator', 'x-drupal-cache'
]

def load_keywords(filepath):
    """Učitaj fingerprint ključne reči iz .txt fajla"""
    keywords = {}
    if not os.path.exists(filepath):
        print(f"{Fore.RED}[!] Keywords file not found: {filepath}{Style.RESET_ALL}")
        return keywords

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):  # preskoči prazne i komentare
                continue
            try:
                tech, words = line.split("=")
                tech = tech.strip()
                words = [w.strip().lower() for w in words.split(",")]
                keywords[tech] = words
            except ValueError:
                continue  # ako linija nije validna
    return keywords


def get_dirb_file():
    """Vrati results/dirb.txt fajl"""
    if not os.path.exists(DIRB_FILE):
        print(f"{Fore.RED}[!] File not found: {DIRB_FILE}{Style.RESET_ALL}")
        sys.exit(1)
    return DIRB_FILE

def clean_html(content):
    """Skini HTML elemente, vrati plain text sa poboljšanjima"""
    try:
        soup = BeautifulSoup(content, "html.parser")
        
        # Ukloni script i style tagove kompletno
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Izvuci text
        text = soup.get_text(separator=" ")
        
        # Očisti whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return text
    except Exception:
        return content

def extract_tech_info(headers, body_text):
    """Izvuci tehnološke informacije koje su korisne za fingerprinting"""
    tech_info = []
    
    # Proveri headers za tehnologije
    tech_headers = ['server', 'x-powered-by', 'x-generator', 'x-drupal-cache', 
                   'x-pingback', 'x-frame-options', 'x-content-type-options']
    
    for header in tech_headers:
        if header in headers:
            tech_info.append(f"Header-{header}: {headers[header]}")
    
    # Traži poznate patterns u body-ju
    body_lower = body_text.lower()
    
    # Generator meta tags
    generator_match = re.search(r'<meta name="generator" content="([^"]+)"', body_text, re.IGNORECASE)
    if generator_match:
        tech_info.append(f"Generator: {generator_match.group(1)}")
    
    # WordPress specific
    if 'wp-content' in body_lower or 'wordpress' in body_lower:
        tech_info.append("CMS: WordPress")
        # Pokušaj da nađeš verziju
        wp_version = re.search(r'wp-includes.*?ver=([0-9.]+)', body_text, re.IGNORECASE)
        if wp_version:
            tech_info.append(f"WordPress-Version: {wp_version.group(1)}")
    
    # Drupal
    if 'drupal' in body_lower or '/sites/all/' in body_lower:
        tech_info.append("CMS: Drupal")
    
    # Joomla
    if 'joomla' in body_lower or '/media/system/' in body_lower:
        tech_info.append("CMS: Joomla")
    
    # PHP errors/info
    php_patterns = [
        r'Fatal error.*?\.php',
        r'Warning.*?\.php',
        r'Notice.*?\.php',
        r'PHP/([0-9.]+)',
        r'phpinfo\(\)'
    ]
    for pattern in php_patterns:
        match = re.search(pattern, body_text, re.IGNORECASE)
        if match:
            tech_info.append(f"PHP-Info: {match.group(0)}")
    
    # JavaScript libraries
    js_libs = ['jquery', 'angular', 'react', 'vue.js', 'bootstrap']
    for lib in js_libs:
        if lib in body_lower:
            # Pokušaj da nađeš verziju
            version_pattern = rf'{lib}[/-]?v?([0-9.]+)'
            version_match = re.search(version_pattern, body_text, re.IGNORECASE)
            if version_match:
                tech_info.append(f"JS-{lib.title()}: {version_match.group(1)}")
            else:
                tech_info.append(f"JS-Library: {lib}")
    
    return tech_info

def fetch_url(url, session):
    """Skini podatke sa URL-a i vrati optimizovan summary"""
    try:
        # Postavi headers kao pravi browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        response = session.get(url, timeout=10, allow_redirects=True, headers=headers)
        response_headers = dict(response.headers) # potencijalna izmena
        # response_headers = {k.lower(): v for k, v in response.headers.items()}

        status_code = response.status_code
        
        # Title
        title = ""
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
        except Exception:
            pass
        
        # Clean body - ograniči na 3000 karaktera za bolju analizu
        body_text = clean_html(response.text)
        if len(body_text) > 3000:
            body_text = body_text[:3000] + "...[truncated]"
        
        # Izvuci tehnološke informacije
        tech_info = extract_tech_info(response_headers, response.text)
        
        # Detektuj login forme
        login_indicators = []
        if re.search(r'<input[^>]*type=["\']password["\']', response.text, re.IGNORECASE):
            login_indicators.append("Login-Form: Present")
        if re.search(r'<form[^>]*login', response.text, re.IGNORECASE):
            login_indicators.append("Login-Form: Detected")
        
        summary = {
            "url": url,
            "status": status_code,
            "title": title,
            "tech_info": tech_info,
            "login_indicators": login_indicators,
            "body_preview": body_text[:500] + "..." if len(body_text) > 500 else body_text,
            "full_body": body_text,
            "interesting_headers": {k: v for k, v in response_headers.items() 
                                  if k.lower() in ['server', 'x-powered-by', 'x-generator', 
                                                  'content-type', 'set-cookie']}
        }
        
        # Color coding based on status
        if status_code == 200:
            color = Fore.GREEN
        elif status_code in [301, 302]:
            color = Fore.CYAN
        elif status_code == 403:
            color = Fore.YELLOW
        else:
            color = Fore.WHITE
            
        print(f"{color}[+] Fetched: {url} (Status {status_code}) - {title[:50]}{Style.RESET_ALL}")
        return summary
        
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Failed to fetch {url}: {str(e)[:100]}{Style.RESET_ALL}")
        return {
            "url": url,
            "status": "Error",
            "title": "",
            "tech_info": [],
            "login_indicators": [],
            "body_preview": "",
            "full_body": "",
            "interesting_headers": {},
            "error": str(e)
        }

def save_machine_readable_results(results):
    """Sačuvaj rezultate u results/fetch.txt za fingerprint.py"""
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    
    try:
        with open(FETCH_FILE, "w", encoding="utf-8") as f:
            for entry in results:
                if entry['status'] == 'Error':
                    continue
                    
                # URL linija
                f.write(f"URL:{entry['url']}\n")
                
                # Status
                f.write(f"STATUS:{entry['status']}\n")
                
                # Title
                if entry['title']:
                    f.write(f"TITLE:{entry['title']}\n")
                
                # Tech info - jedna po liniji za lakše parsiranje
                for tech in entry['tech_info']:
                    f.write(f"TECH:{tech}\n")
                
                # Login indicators
                for login in entry['login_indicators']:
                    f.write(f"LOGIN:{login}\n")
                
                # Important headers
                for header, value in entry['interesting_headers'].items():
                    f.write(f"HEADER:{header}:{value}\n")
                
                # Body text za keyword matching
                if entry['full_body']:
                    # Podeli body na keywords koje fingerprint može da traži
                    body_words = re.findall(r'\b\w+\b', entry['full_body'].lower())
                    fingerprint_words = [word for word in body_words if word in FINGERPRINT_KEYWORDS]
                    
                    if fingerprint_words:
                        f.write(f"KEYWORDS:{','.join(set(fingerprint_words))}\n")
                    
                    # Čuvaj i ceo body za detaljniju analizu
                    f.write(f"BODY:{entry['full_body']}\n")
                
                # Separator između unosa
                f.write("---\n")
        
        print(f"{Fore.GREEN}[+] Machine readable results saved: {FETCH_FILE}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error saving machine readable results: {e}{Style.RESET_ALL}")

def save_report(results):
    """Sačuvaj detaljan summary u reports/fetch_*.txt"""
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    
    timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    filename = os.path.join(REPORTS_DIR, f"fetch_{timestamp}.txt")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("Fetcher Results - Detailed Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total URLs: {len(results)}\n")
        f.write(f"Successful: {len([r for r in results if r['status'] != 'Error'])}\n")
        f.write(f"Failed: {len([r for r in results if r['status'] == 'Error'])}\n")
        f.write("\n" + "=" * 60 + "\n\n")
        
        for entry in results:
            f.write("=" * 60 + "\n")
            f.write(f"URL: {entry['url']}\n")
            f.write(f"Status: {entry['status']}\n")
            
            if entry['status'] != 'Error':
                f.write(f"Title: {entry['title']}\n")
                
                if entry['tech_info']:
                    f.write("\nTechnology Information:\n")
                    for tech in entry['tech_info']:
                        f.write(f"  - {tech}\n")
                
                if entry['login_indicators']:
                    f.write("\nLogin Indicators:\n")
                    for login in entry['login_indicators']:
                        f.write(f"  - {login}\n")
                
                if entry['interesting_headers']:
                    f.write("\nInteresting Headers:\n")
                    for k, v in entry['interesting_headers'].items():
                        f.write(f"  {k}: {v}\n")
                
                f.write(f"\nBody Preview:\n{entry['body_preview']}\n")
            else:
                f.write(f"Error: {entry.get('error', 'Unknown error')}\n")
            
            f.write("\n")
    
    print(f"{Fore.CYAN}[+] Detailed report saved: {filename}{Style.RESET_ALL}")

def main():
    global FINGERPRINT_KEYWORDS
    FINGERPRINT_KEYWORDS = load_keywords(KEYWORDS_FILE)
    print(f"{Fore.CYAN}[*] Fetcher v2.0 - Enhanced URL Content Fetcher{Style.RESET_ALL}")
    print("=" * 60)
    
    # Učitaj dirb report
    latest_report = get_dirb_file()
    print(f"{Fore.CYAN}[*] Using dirb report: {latest_report}{Style.RESET_ALL}")
    
    urls = []
    with open(latest_report, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
    
    if not urls:
        print(f"{Fore.RED}[!] No valid URLs found in {latest_report}{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.CYAN}[*] Found {len(urls)} URLs to fetch{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Starting multi-threaded fetch...{Style.RESET_ALL}")
    
    results = []
    
    # Koristi session za connection pooling
    session = requests.Session()
    
    # Multi-threaded fetching za bolju performansu
    # Mozemo eventualno izmeniti tako da korisnik moze da u komandnoj liniji zada broj niti, tu bi koristili argparse
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(fetch_url, url, session): url for url in urls}
        
        for future in as_completed(future_to_url):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                url = future_to_url[future]
                print(f"{Fore.RED}[!] Exception for {url}: {e}{Style.RESET_ALL}")
                results.append({
                    "url": url,
                    "status": "Error",
                    "title": "",
                    "tech_info": [],
                    "login_indicators": [],
                    "body_preview": "",
                    "full_body": "",
                    "interesting_headers": {},
                    "error": str(e)
                })
    
    print("\n" + "=" * 60)
    print(f"{Fore.GREEN}[+] Fetching completed!{Style.RESET_ALL}")
    print(f"Total URLs processed: {len(results)}")
    print(f"Successful: {len([r for r in results if r['status'] != 'Error'])}")
    print(f"Failed: {len([r for r in results if r['status'] == 'Error'])}")
    
    # Sačuvaj oba tipa rezultata
    save_report(results)
    save_machine_readable_results(results)

if __name__ == "__main__":
    main()