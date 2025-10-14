#!/usr/bin/env python3
import sys
import socket
import datetime
import os
import re
import time
from collections import defaultdict
from colorama import Fore, Style, init

# Inicijalizacija colorama
init(autoreset=True)

# Lista portova koje proveravamo
HTTP_PORTS = [80, 8080, 8000, 8001, 8008, 8888, 9000, 443]

# Probe request-ovi za različite servere
HTTP_PROBES = [
    "GET / HTTP/1.0\r\n\r\n",
    "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
    "GET /server-info HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
    "GET /server-status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
    "OPTIONS / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
    "GET /admin HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n"
]

# Regex paterni za identifikaciju servera
SERVER_SIGNATURES = {
    'Apache': [
        r'Server:\s*Apache[/\s]([0-9\.]+)',
        r'Apache[/\s]([0-9\.]+)',
        r'Server:\s*Apache'
    ],
    'Nginx': [
        r'Server:\s*nginx[/\s]([0-9\.]+)',
        r'nginx[/\s]([0-9\.]+)',
        r'Server:\s*nginx'
    ],
    'Microsoft-IIS': [
        r'Server:\s*Microsoft-IIS[/\s]([0-9\.]+)',
        r'Microsoft-IIS[/\s]([0-9\.]+)',
        r'Server:\s*Microsoft-IIS'
    ],
    'Python': [
        r'Server:\s*SimpleHTTP[/\s]([0-9\.]+)\s*Python[/\s]([0-9\.]+)',
        r'Server:\s*Python[/\s]([0-9\.]+)',
        r'Server:\s*.*Python.*',
        r'BaseHTTP[/\s]([0-9\.]+)'
    ],
    'Node.js': [
        r'X-Powered-By:\s*Express',
        r'Server:\s*.*[Nn]ode\.?[Jj][Ss].*',
        r'Server:\s*.*Express.*'
    ],
    'Tomcat': [
        r'Server:\s*Apache-Coyote[/\s]([0-9\.]+)',
        r'Server:\s*.*Tomcat[/\s]([0-9\.]+)',
        r'Server:\s*.*Tomcat.*'
    ],
    'Jetty': [
        r'Server:\s*Jetty\(([0-9\.]+)\)',
        r'Server:\s*.*Jetty.*'
    ],
    'Lighttpd': [
        r'Server:\s*lighttpd[/\s]([0-9\.]+)',
        r'Server:\s*lighttpd'
    ],
    'Caddy': [
        r'Server:\s*Caddy',
        r'Server:\s*.*Caddy.*'
    ],
    'Cherokee': [
        r'Server:\s*Cherokee[/\s]([0-9\.]+)',
        r'Server:\s*Cherokee'
    ]
}

def scan_ports(target_ip):
    """Scanning ports for HTTP servers"""
    open_ports = []
    for port in HTTP_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"[!] Error occured while scanning a port {port}: {e}")
    return open_ports

def identify_server(response_text):
    """Identifitaion of HTTP server and its version"""
    server_info = {
        'name': 'Unknown',
        'version': 'Unknown',
        'full_header': None,
        'confidence': 'Low'
    }
    
    if not response_text:
        return server_info
    
    # Tražimo Server header
    server_match = re.search(r'Server:\s*([^\r\n]+)', response_text, re.IGNORECASE)
    if server_match:
        server_info['full_header'] = server_match.group(1).strip()
    
    # Proveravamo sve poznate servere
    for server_name, patterns in SERVER_SIGNATURES.items():
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                server_info['name'] = server_name
                server_info['confidence'] = 'High'
                
                # Pokušavamo da izvučemo verziju
                groups = match.groups()
                if groups:
                    # Za Python SimpleHTTP server koji ima i Python verziju
                    if server_name == 'Python' and len(groups) >= 2:
                        server_info['version'] = f"SimpleHTTP/{groups[0]} Python/{groups[1]}"
                    else:
                        server_info['version'] = groups[0]
                
                return server_info
    
    # Pokušaj da identifikujemo na osnovu drugih header-a
    additional_headers = {
        'X-Powered-By': response_text,
        'X-AspNet-Version': response_text,
        'X-Generator': response_text
    }
    
    for header, text in additional_headers.items():
        header_match = re.search(rf'{header}:\s*([^\r\n]+)', text, re.IGNORECASE)
        if header_match:
            value = header_match.group(1).strip()
            if 'PHP' in value.upper():
                server_info['name'] = 'PHP'
                server_info['version'] = value
                server_info['confidence'] = 'Medium'
            elif 'ASP.NET' in value.upper():
                server_info['name'] = 'ASP.NET'
                server_info['version'] = value
                server_info['confidence'] = 'Medium'
    
    return server_info

def enhanced_banner_grab(target_ip, port):
    """Enhanced banner grab with server analysis"""
    all_responses = []
    server_info = None
    
    for i, probe in enumerate(HTTP_PROBES):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, port))
            
            # Formatiramo zahtev
            request = probe.format(target_ip) if "{}" in probe else probe
            sock.send(request.encode())
            
            try:
                response = sock.recv(4096).decode(errors="ignore")
                if response:
                    all_responses.append(response)
                    
                    # Analiziramo prvi uspešan odgovor za server info
                    if not server_info or server_info['confidence'] != 'High':
                        temp_info = identify_server(response)
                        if temp_info['confidence'] == 'High' or not server_info:
                            server_info = temp_info
                            
            except socket.timeout:
                pass
            
            sock.close()
            
        except Exception as e:
            continue
    
    if not server_info:
        server_info = {
            'name': 'Unknown',
            'version': 'Unknown',
            'full_header': None,
            'confidence': 'Low'
        }
    
    return all_responses, server_info

def display_server_info(server_info):
    """Display information about HTTP server"""
    print(f"       Server: {server_info['name']}")
    print(f"       Version: {server_info['version']}")
    if server_info['full_header']:
        print(f"       Header: {server_info['full_header']}")
    print(f"       Confidence: {server_info['confidence']}")

def save_enhanced_report(target_ip, results, execution_time):
    """Saving a detailed report"""
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    filename = f"reports/http_scan_{timestamp}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"HTTP Server Scan Results for {target_ip}\n")
        f.write("=" * 60 + "\n")
        f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {target_ip}\n")
        f.write(f"Execution Time: {execution_time:.2f} seconds\n\n")
        
        if results:
            f.write("DISCOVERED HTTP SERVERS:\n")
            f.write("-" * 30 + "\n\n")
            
            for port, data in results.items():
                server_info = data['server_info']
                responses = data['responses']
                
                f.write(f"Port: {port}\n")
                f.write(f"Server: {server_info['name']}\n")
                f.write(f"Version: {server_info['version']}\n")
                f.write(f"Confidence: {server_info['confidence']}\n")
                
                if server_info['full_header']:
                    f.write(f"Full Server Header: {server_info['full_header']}\n")
                
                f.write("\nRaw Responses:\n")
                for i, response in enumerate(responses[:2]):  # Samo prva dva odgovora
                    f.write(f"  Response {i+1}:\n")
                    lines = response.split('\n')[:10]  # Samo prvih 10 linija
                    for line in lines:
                        f.write(f"    {line.strip()}\n")
                    f.write("\n")
                
                f.write("-" * 50 + "\n\n")
        else:
            f.write("No HTTP servers found on scanned ports.\n")
    
    print("Finished")
    print("=" * 70)
    print(f"{Fore.GREEN}[+] Detailed report is saved in: {filename}{Style.RESET_ALL}")

def main():
    # Pokretanje merenja vremena
    start_time = time.time()
    
    if len(sys.argv) != 2:
        print(f"{Fore.CYAN}[*] Use case: python3 {sys.argv[0]} <IP>{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Example: python3 {sys.argv[0]} 192.168.1.1{Style.RESET_ALL}")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    # Validacija IP adrese
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print(f"{Fore.RED}[!] Invalid IP address!{Style.RESET_ALL}")
        sys.exit(1)
    
    #print("=" * 70)
    print(f"[*] Scanning {target_ip} for HTTP servers on ports {HTTP_PORTS}...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] This could take a few seconds...\n{Style.RESET_ALL}")
    
    # Skeniranje portova
    open_ports = scan_ports(target_ip)
    results = {}
    
    if open_ports:
        print("=" * 70)
        print(f"{Fore.GREEN}[+] Found open ports: {open_ports}\n{Style.RESET_ALL}")
        print("=" * 70)
        
        for port in open_ports:
            print(f"{Fore.CYAN}[*] Analyzing port {port}...{Style.RESET_ALL}")
            responses, server_info = enhanced_banner_grab(target_ip, port)
            
            if responses:
                results[port] = {
                    'server_info': server_info,
                    'responses': responses
                }
                
                print(f"{Fore.GREEN}[+] Port {port} - HTTP server detected:{Style.RESET_ALL}")
                display_server_info(server_info)
                print("=" * 70)
                print()
            else:
                print(f"{Fore.RED}[-] Port {port} - No HTTP answer{Style.RESET_ALL}\n")
                print()
    else:
        print(f"{Fore.RED}[-] No open HTTP ports were found on target machine.{Style.RESET_ALL}")
    
    # Završetak merenja vremena
    end_time = time.time()
    execution_time = end_time - start_time
    
    # Čuvanje izveštaja
    if results:
        save_enhanced_report(target_ip, results, execution_time)
        
        # Sažetak
        print("\n" + "=" * 70)
        print("SCAN SUMMARY:")
        print("=" * 70)
        for port, data in results.items():
            server = data['server_info']
            print(f"Port {port}: {Fore.GREEN}{server['name']} {server['version']} ({server['confidence']} confidence){Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}[!] No HTTP servers were found on target IP.{Style.RESET_ALL}")
    
    # Prikaz vremena izvršavanja
    print("\n" + "=" * 70)
    print(f"{Fore.CYAN}[*] Total execution time: {execution_time:.2f} seconds{Style.RESET_ALL}")
    print("=" * 70)

if __name__ == "__main__":
    main()