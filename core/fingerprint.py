#!/usr/bin/env python3
import os
import sys
import re
import datetime
from colorama import Fore, Style, init

# Init colorama
init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
KEYWORDS_DIR = os.path.join(BASE_DIR, "..", "data", "keywords")

FETCH_FILE = os.path.join(RESULTS_DIR, "fetch.txt")
FINGERPRINT_RESULTS = os.path.join(RESULTS_DIR, "fingerprint.txt")

# Keyword fajlovi
KEYWORD_FILES = {
    'admin_panels': os.path.join(KEYWORDS_DIR, 'admin_panels.txt'),
    'backend': os.path.join(KEYWORDS_DIR, 'backend.txt'),
    'frontend': os.path.join(KEYWORDS_DIR, 'frontend.txt'),
    'cms': os.path.join(KEYWORDS_DIR, 'cms.txt'),
    'runtimes': os.path.join(KEYWORDS_DIR, 'runtimes.txt'),
    'web_servers': os.path.join(KEYWORDS_DIR, 'web_servers.txt')
}

class TechnologyFingerprinter:
    def __init__(self):
        self.keywords = {}
        self.detected_technologies = {}
        
    def load_keywords(self):
        """Učitaj sve keyword fajlove"""
        print(f"{Fore.CYAN}[*] Loading fingerprint keywords...{Style.RESET_ALL}")
        
        for category, filepath in KEYWORD_FILES.items():
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        keywords = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
                        self.keywords[category] = keywords
                        print(f"{Fore.GREEN}[+] Loaded {len(keywords)} keywords from {category}.txt{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error loading {category}.txt: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Keyword file not found: {filepath}{Style.RESET_ALL}")
        
        total_keywords = sum(len(kw) for kw in self.keywords.values())
        print(f"{Fore.CYAN}[*] Total keywords loaded: {total_keywords}{Style.RESET_ALL}")
        
    def parse_fetch_data(self):
        """Parsiraj fetch.txt fajl"""
        if not os.path.exists(FETCH_FILE):
            print(f"{Fore.RED}[!] Fetch file not found: {FETCH_FILE}{Style.RESET_ALL}")
            sys.exit(1)
            
        print(f"{Fore.CYAN}[*] Parsing fetch data...{Style.RESET_ALL}")
        
        urls_data = {}
        current_url = None
        
        with open(FETCH_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                
                if line.startswith('URL:'):
                    current_url = line[4:]  # Remove 'URL:' prefix
                    urls_data[current_url] = {
                        'status': '',
                        'title': '',
                        'tech_info': [],
                        'headers': {},
                        'body': '',
                        'keywords': []
                    }
                elif line.startswith('STATUS:') and current_url:
                    urls_data[current_url]['status'] = line[7:]
                elif line.startswith('TITLE:') and current_url:
                    urls_data[current_url]['title'] = line[6:]
                elif line.startswith('TECH:') and current_url:
                    urls_data[current_url]['tech_info'].append(line[5:])
                elif line.startswith('HEADER:') and current_url:
                    header_data = line[7:]
                    if ':' in header_data:
                        key, value = header_data.split(':', 1)
                        urls_data[current_url]['headers'][key] = value
                elif line.startswith('KEYWORDS:') and current_url:
                    keywords = line[9:].split(',')
                    urls_data[current_url]['keywords'].extend(keywords)
                elif line.startswith('BODY:') and current_url:
                    urls_data[current_url]['body'] = line[5:]
                elif line == '---':
                    current_url = None
                    
        print(f"{Fore.GREEN}[+] Parsed data for {len(urls_data)} URLs{Style.RESET_ALL}")
        return urls_data
    
    def detect_technologies(self, urls_data):
        """Detektuj tehnologije na osnovu keywords"""
        print(f"{Fore.CYAN}[*] Starting technology detection...{Style.RESET_ALL}")
        
        for url, data in urls_data.items():
            detected = {}
            confidence_scores = {}
            matched_terms = []  # Lista svih pronađenih termina za exploit pretragu
            
            # Kombiniraj sav tekst za analizu
            text_to_analyze = f"{data['title']} {' '.join(data['tech_info'])} {' '.join(data['keywords'])} {data['body']}"
            text_lower = text_to_analyze.lower()
            
            # Dodaj header informacije
            header_text = ""
            for header, value in data['headers'].items():
                header_text += f" {header} {value}"
            text_to_analyze += header_text
            text_lower += header_text.lower()
            
            # Proverava svaku kategoriju keywords
            for category, keywords in self.keywords.items():
                matches = []
                category_terms = []
                
                for keyword in keywords:
                    # Različiti načini pretrage za različite tipove
                    patterns = [
                        rf'\b{re.escape(keyword)}\b',  # Exact word match
                        rf'{re.escape(keyword)}',      # Substring match
                        rf'{re.escape(keyword)}/[\d.]+',  # Version pattern
                        rf'{re.escape(keyword)}-[\d.]+',   # Version with dash
                    ]
                    
                    for pattern in patterns:
                        matches_found = re.finditer(pattern, text_lower, re.IGNORECASE)
                        for match in matches_found:
                            match_text = match.group(0)
                            if match_text not in matches:
                                matches.append(match_text)
                                
                                # Dodaj osnovni term (bez verzije) za exploit pretragu
                                base_term = re.sub(r'[/\-][\d.]+.*', '', keyword).strip()
                                if base_term and base_term not in category_terms:
                                    category_terms.append(base_term)
                                
                                # Pokušaj da izvučeš verziju
                                version_match = re.search(r'[\d.]+', match_text)
                                if version_match:
                                    version = version_match.group(0)
                                    version_term = f"{base_term} {version}"
                                    if version_term not in category_terms:
                                        category_terms.append(version_term)
                
                if matches:
                    detected[category] = list(set(matches))
                    confidence_scores[category] = len(matches)
                    matched_terms.extend(category_terms)
            
            # Dodatna detekcija na osnovu header-a
            header_terms = self._detect_from_headers(data['headers'], detected, confidence_scores)
            matched_terms.extend(header_terms)
            
            # Detekcija CMS-a na osnovu specifičnih pattern-a
            cms_terms = self._detect_cms_patterns(text_lower, detected, confidence_scores)
            matched_terms.extend(cms_terms)
            
            if detected:
                # Ukloni duplikate iz matched_terms
                unique_terms = list(set(matched_terms))
                
                self.detected_technologies[url] = {
                    'technologies': detected,
                    'confidence': confidence_scores,
                    'status': data['status'],
                    'title': data['title'],
                    'search_terms': unique_terms  # Termini za exploit pretragu
                }
                
                tech_summary = []
                for category, items in detected.items():
                    tech_summary.extend([f"{category.upper()}: {item}" for item in items[:3]])  # Top 3 per category
                
                print(f"{Fore.GREEN}[+] {url}{Style.RESET_ALL}")
                for tech in tech_summary[:5]:  # Show top 5 overall
                    print(f"    {Fore.YELLOW}└─ {tech}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}└─ Search terms for exploits: {len(unique_terms)}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}[*] Technology detection completed. Found technologies on {len(self.detected_technologies)} URLs{Style.RESET_ALL}")
    
    def _detect_from_headers(self, headers, detected, confidence_scores):
        """Posebna detekcija na osnovu HTTP header-a"""
        header_terms = []
        header_mappings = {
            'server': 'web_servers',
            'x-powered-by': 'runtimes',
            'x-generator': 'cms'
        }
        
        for header_name, category in header_mappings.items():
            if header_name in headers:
                header_value = headers[header_name].lower()
                if category not in detected:
                    detected[category] = []
                detected[category].append(f"Header: {header_value}")
                confidence_scores[category] = confidence_scores.get(category, 0) + 5  # High confidence for headers
                
                # Dodaj term za pretragu (bez "header:" prefiksa)
                clean_value = re.sub(r'[/\d.].*', '', header_value).strip()
                if clean_value and len(clean_value) > 2:
                    header_terms.append(clean_value)
        
        return header_terms
    
    def _detect_cms_patterns(self, text, detected, confidence_scores):
        """Detekcija CMS-a na osnovu specifičnih pattern-a"""
        cms_terms = []
        cms_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'wordpress', r'/wp-admin/', r'wp_'],
            'Drupal': [r'/sites/all/', r'/modules/', r'drupal', r'sites/default'],
            'Joomla': [r'/media/system/', r'joomla', r'/administrator/', r'com_content'],
            'Magento': [r'/skin/frontend/', r'magento', r'/app/design/', r'mage'],
            'PrestaShop': [r'/modules/prestashop', r'prestashop', r'/themes/default/']
        }
        
        for cms, patterns in cms_patterns.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches += 1
            
            if matches >= 2:  # Potrebno minimum 2 match-a za CMS detekciju
                if 'cms' not in detected:
                    detected['cms'] = []
                detected['cms'].append(f"CMS: {cms}")
                confidence_scores['cms'] = confidence_scores.get('cms', 0) + matches * 3
                
                # Dodaj CMS name za pretragu
                cms_terms.append(cms.lower())
        
        return cms_terms
    
    def get_all_search_terms(self):
        """Vrati sve jedinstvene search termine za exploit pretragu"""
        all_terms = set()
        for url_data in self.detected_technologies.values():
            all_terms.update(url_data.get('search_terms', []))
        
        # Filtriraj kratke ili nekorisne termine
        filtered_terms = []
        for term in all_terms:
            if len(term) > 2 and not re.match(r'^[\d\.\-/]+$', term):  # Ignoriši samo brojeve/verzije
                filtered_terms.append(term)
        
        return sorted(filtered_terms)
    
    def save_machine_readable_results(self):
        """Sačuvaj sažete rezultate u results/fingerprint.txt"""
        if not os.path.exists(RESULTS_DIR):
            os.makedirs(RESULTS_DIR)

        try:
            all_search_terms = self.get_all_search_terms()
            with open(FINGERPRINT_RESULTS, 'w', encoding='utf-8') as f:
                #f.write("=== SUMMARY OF SEARCH TERMS ===\n")
                #f.write(f"TOTAL_SEARCH_TERMS:{len(all_search_terms)}\n\n")

                if all_search_terms:
                    for term in all_search_terms[:10]:  # prvih 10 termina
                        f.write(f"{term}\n")

                    if len(all_search_terms) > 10:
                        f.write(f"\n... and {len(all_search_terms) - 10} more\n")

            print(f"{Fore.GREEN}[+] Machine readable results saved: {FINGERPRINT_RESULTS}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving machine readable results: {e}{Style.RESET_ALL}")
    

    def save_detailed_report(self):
        """Sačuvaj detaljan izveštaj"""
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
        
        timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        filename = os.path.join(REPORTS_DIR, f"fingerprint_{timestamp}.txt")
        
        all_search_terms = self.get_all_search_terms()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Technology Fingerprinting Report\n")
            f.write("=" * 70 + "\n")
            f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"URLs Analyzed: {len(self.detected_technologies)}\n")
            f.write(f"Total Search Terms Generated: {len(all_search_terms)}\n")
            f.write("\n" + "=" * 70 + "\n\n")
            
            # Technology detection results
            f.write("DETECTED TECHNOLOGIES BY URL:\n")
            f.write("-" * 40 + "\n")
            
            for url, data in self.detected_technologies.items():
                f.write(f"\nURL: {url}\n")
                f.write(f"Status: {data['status']}\n")
                f.write(f"Title: {data['title']}\n")
                f.write("Technologies:\n")
                
                for category, items in data['technologies'].items():
                    f.write(f"  {category.upper()}:\n")
                    for item in items:
                        f.write(f"    - {item}\n")
                
                f.write(f"Confidence Scores: {data['confidence']}\n")
                f.write("Search Terms for this URL:\n")
                for term in data.get('search_terms', []):
                    f.write(f"  - {term}\n")
            
            # All search terms summary
            f.write(f"\n{'-' * 60}\n")
            f.write("ALL SEARCH TERMS FOR EXPLOIT SEARCH:\n")
            f.write("-" * 40 + "\n")
            f.write("These terms can be used by exploit_search.py for finding vulnerabilities:\n\n")
            
            for i, term in enumerate(all_search_terms, 1):
                f.write(f"{i:3d}. {term}\n")
        
        print(f"{Fore.CYAN}[+] Detailed report saved: {filename}{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}Fingerprint v1.0 - Technology Detection{Style.RESET_ALL}")
    print("=" * 70)
    
    fingerprinter = TechnologyFingerprinter()
    
    # Step 1: Load keywords
    fingerprinter.load_keywords()
    
    if not fingerprinter.keywords:
        print(f"{Fore.RED}[!] No keywords loaded. Check your keywords directory.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Step 2: Parse fetch data
    urls_data = fingerprinter.parse_fetch_data()
    
    if not urls_data:
        print(f"{Fore.RED}[!] No data found in fetch.txt{Style.RESET_ALL}")
        sys.exit(1)
    
    # Step 3: Detect technologies
    fingerprinter.detect_technologies(urls_data)
    
    # Step 4: Save results
    fingerprinter.save_machine_readable_results()
    fingerprinter.save_detailed_report()
    
    # Summary
    print("\n" + "=" * 70)
    print(f"{Fore.GREEN}[+] Fingerprinting completed!{Style.RESET_ALL}")
    print(f"URLs with detected technologies: {len(fingerprinter.detected_technologies)}")
    
    all_search_terms = fingerprinter.get_all_search_terms()
    print(f"Search terms generated for exploit search: {len(all_search_terms)}")
    
    if all_search_terms:
        print(f"{Fore.CYAN}[*] Top search terms:{Style.RESET_ALL}")
        for term in all_search_terms[:10]:  # Show first 10 terms
            print(f"  - {term}")
        
        if len(all_search_terms) > 10:
            print(f"  ... and {len(all_search_terms) - 10} more")
    
    print(f"\n{Fore.YELLOW}[*] Search terms saved in {FINGERPRINT_RESULTS}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] These can be used by exploit_search.py for vulnerability research{Style.RESET_ALL}")

if __name__ == "__main__":
    main()