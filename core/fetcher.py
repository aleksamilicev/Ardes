#!/usr/bin/env python3
import os
import sys
import glob
import datetime
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Init colorama
init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DIRB_FILE = os.path.join(RESULTS_DIR, "dirb.txt")

def get_dirb_file():
    """Vrati results/dirb.txt fajl"""
    if not os.path.exists(DIRB_FILE):
        print(f"{Fore.RED}[!] File not found: {DIRB_FILE}{Style.RESET_ALL}")
        sys.exit(1)
    return DIRB_FILE

def clean_html(content):
    """Skini HTML elemente, vrati plain text"""
    try:
        soup = BeautifulSoup(content, "html.parser")
        return soup.get_text(separator="\n")
    except Exception:
        return content

def fetch_url(url):
    """Skini podatke sa URL-a i vrati summary"""
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers

        # Status
        status_code = response.status_code

        # Title
        title = ""
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
        except Exception:
            pass

        # Clean body
        body_text = clean_html(response.text)
        body_text = body_text[:2000]  # Limit na 2000 karaktera da ne bude predugačko

        summary = {
            "url": url,
            "status": status_code,
            "headers": dict(headers),
            "title": title,
            "body": body_text
        }

        print(f"{Fore.GREEN}[+] Fetched: {url} (Status {status_code}){Style.RESET_ALL}")
        return summary

    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Failed to fetch {url}: {e}{Style.RESET_ALL}")
        return {
            "url": url,
            "status": "Error",
            "headers": {},
            "title": "",
            "body": ""
        }

def save_report(results):
    """Sačuvaj summary u reports/fetch_*.txt"""
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

    timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    filename = os.path.join(REPORTS_DIR, f"fetch_{timestamp}.txt")

    with open(filename, "w", encoding="utf-8") as f:
        for entry in results:
            f.write("="*60 + "\n")
            f.write(f"URL: {entry['url']}\n")
            f.write(f"Status: {entry['status']}\n")
            f.write(f"Title: {entry['title']}\n")

            if entry["headers"]:
                f.write("Headers:\n")
                for k, v in entry["headers"].items():
                    f.write(f"  {k}: {v}\n")

            f.write("\nBody (cleaned):\n")
            f.write(entry["body"])
            f.write("\n\n")

    print(f"{Fore.CYAN}[+] Report saved: {filename}{Style.RESET_ALL}")

def main():
    # Učitaj poslednji dirb report
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

    results = []
    for url in urls:
        results.append(fetch_url(url))

    save_report(results)

if __name__ == "__main__":
    main()
