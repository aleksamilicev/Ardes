#!/usr/bin/env python3
import sys
import os
import subprocess
import socket
import time
import json
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ArdesOrchestrator:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.core_dir = os.path.join(self.base_dir, "core")
        self.results_dir = os.path.join(self.core_dir, "results")
        self.reports_dir = os.path.join(self.core_dir, "reports")
        
        # Paths to scripts
        self.scanner_script = os.path.join(self.core_dir, "scanner.py")
        self.dirbuster_script = os.path.join(self.core_dir, "dirbuster.py")
        self.fetcher_script = os.path.join(self.core_dir, "fetcher.py")
        self.fingerprint_script = os.path.join(self.core_dir, "fingerprint.py")
        
        # Check if all scripts exist
        self.verify_scripts()
    
    def verify_scripts(self):
        """Verify that all required scripts exist"""
        scripts = [
            ("scanner.py", self.scanner_script),
            ("dirbuster.py", self.dirbuster_script),
            ("fetcher.py", self.fetcher_script),
            ("fingerprint.py", self.fingerprint_script)
        ]
        
        missing_scripts = []
        for name, path in scripts:
            if not os.path.exists(path):
                missing_scripts.append(name)
        
        if missing_scripts:
            print(f"{Fore.RED}[!] Missing scripts in core/ directory: {', '.join(missing_scripts)}{Style.RESET_ALL}")
            sys.exit(1)
    
    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def print_banner(self):
        """Print ARDES banner"""
        print("=" * 70)
        print(f"{Fore.CYAN}    ╔═╗╦═╗╔╦╗╔═╗╔═╗  ┌─┐┬ ┬┌┬┐┌─┐┌┬┐┌─┐┌┬┐┌─┐┌┬┐  ╦═╗┌─┐┌─┐┌─┐┌┐┌{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    ╠═╣╠╦╝ ║║║╣ ╚═╗  ├─┤│ │ │ │ ││││├─┤ │ ├┤  ││  ╠╦╝├┤ │  │ ││││{Style.RESET_ALL}")
        print(f"{Fore.CYAN}    ╩ ╩╩╚══╩╝╚═╝╚═╝  ┴ ┴└─┘ ┴ └─┘┴ ┴┴ ┴ ┴ └─┘─┴┘  ╩╚═└─┘└─┘└─┘┘└┘{Style.RESET_ALL}")
        print(f"{Fore.WHITE}                    Automated Recon & Detection Suite{Style.RESET_ALL}")
        print(f"{Fore.WHITE}                             by A13k5a M1l1c3v{Style.RESET_ALL}")
        print("=" * 70)
        print(f"{Fore.YELLOW}[*] Target: {self.target_ip}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Workflow: Scanner → DirBuster → Fetcher → Fingerprint{Style.RESET_ALL}")
        print("=" * 70)
    
    def run_scanner(self):
        """Run scanner.py to find open HTTP ports"""
        print(f"\n{Fore.CYAN}[STEP 1] Running HTTP port scanner...{Style.RESET_ALL}")
        print("=" * 70)
        
        try:
            # Change to core directory to run scanner
            original_cwd = os.getcwd()
            os.chdir(self.core_dir)
            
            result = subprocess.run(
                [sys.executable, "scanner.py", self.target_ip],
                capture_output=True,
                text=True,
                encoding='utf-8'
            )
            
            # Return to original directory
            os.chdir(original_cwd)
            
            print(result.stdout)
            if result.stderr:
                print(f"{Fore.RED}[!] Scanner errors: {result.stderr}{Style.RESET_ALL}")
            
            if result.returncode != 0:
                print(f"{Fore.RED}[!] Scanner failed with return code: {result.returncode}{Style.RESET_ALL}")
                return []
            
            # Parse scanner output to find open ports
            open_ports = self.parse_scanner_output(result.stdout)
            return open_ports
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error running scanner: {e}{Style.RESET_ALL}")
            return []
    
    def parse_scanner_output(self, output):
        """Parse scanner output to extract open ports"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            # Look for lines that mention open ports
            if "Found open ports:" in line:
                # Extract ports from format like: "[+] Found open ports: [80, 443, 8080]"
                import re
                ports_match = re.search(r'\[([0-9, ]+)\]', line)
                if ports_match:
                    ports_str = ports_match.group(1)
                    ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()]
                    open_ports.extend(ports)
            elif "Port" in line and "HTTP server detected" in line:
                # Alternative parsing for individual port lines
                import re
                port_match = re.search(r'Port (\d+)', line)
                if port_match:
                    port = int(port_match.group(1))
                    if port not in open_ports:
                        open_ports.append(port)
        
        return sorted(list(set(open_ports)))  # Remove duplicates and sort
    
    def run_dirbuster(self, ports):
        """Run dirbuster.py for each discovered port"""
        print(f"\n{Fore.CYAN}[STEP 2] Running directory enumeration...{Style.RESET_ALL}")
        print("=" * 70)
        
        if not ports:
            print(f"{Fore.YELLOW}[!] No HTTP ports found, skipping directory enumeration{Style.RESET_ALL}")
            return False
        
        all_success = True
        
        for port in ports:
            print(f"\n{Fore.YELLOW}[*] Running DirBuster on port {port}...{Style.RESET_ALL}")
            
            try:
                # Change to core directory to run dirbuster
                original_cwd = os.getcwd()
                os.chdir(self.core_dir)
                
                result = subprocess.run(
                    [sys.executable, "dirbuster.py", self.target_ip, str(port)],
                    text=True,
                    encoding='utf-8'
                )
                
                # Return to original directory
                os.chdir(original_cwd)
                
                if result.returncode != 0:
                    print(f"{Fore.RED}[!] DirBuster failed for port {port} with return code: {result.returncode}{Style.RESET_ALL}")
                    all_success = False
                else:
                    print(f"{Fore.GREEN}[+] DirBuster completed for port {port}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[!] Error running DirBuster on port {port}: {e}{Style.RESET_ALL}")
                all_success = False
        
        return all_success
    
    def run_fetcher(self):
        """Run fetcher.py to grab content from discovered URLs"""
        print(f"\n{Fore.CYAN}[STEP 3] Running content fetcher...{Style.RESET_ALL}")
        print("=" * 70)
        
        # Check if dirb.txt exists
        dirb_file = os.path.join(self.results_dir, "dirb.txt")
        if not os.path.exists(dirb_file):
            print(f"{Fore.YELLOW}[!] No dirb.txt found, skipping content fetching{Style.RESET_ALL}")
            return False
        
        # Check if dirb.txt has content
        try:
            with open(dirb_file, 'r') as f:
                content = f.read().strip()
                if not content:
                    print(f"{Fore.YELLOW}[!] dirb.txt is empty, skipping content fetching{Style.RESET_ALL}")
                    return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading dirb.txt: {e}{Style.RESET_ALL}")
            return False
        
        try:
            # Change to core directory to run fetcher
            original_cwd = os.getcwd()
            os.chdir(self.core_dir)
            
            result = subprocess.run(
                [sys.executable, "fetcher.py"],
                text=True,
                encoding='utf-8'
            )
            
            # Return to original directory
            os.chdir(original_cwd)
            
            if result.returncode != 0:
                print(f"{Fore.RED}[!] Fetcher failed with return code: {result.returncode}{Style.RESET_ALL}")
                return False
            else:
                print(f"{Fore.GREEN}[+] Content fetching completed{Style.RESET_ALL}")
                return True
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error running fetcher: {e}{Style.RESET_ALL}")
            return False
    
    def run_fingerprint(self):
        """Run fingerprint.py to detect technologies"""
        print(f"\n{Fore.CYAN}[STEP 4] Running technology fingerprinting...{Style.RESET_ALL}")
        print("=" * 70)
        
        # Check if fetch.txt exists
        fetch_file = os.path.join(self.results_dir, "fetch.txt")
        if not os.path.exists(fetch_file):
            print(f"{Fore.YELLOW}[!] No fetch.txt found, skipping fingerprinting{Style.RESET_ALL}")
            return False
        
        try:
            # Change to core directory to run fingerprint
            original_cwd = os.getcwd()
            os.chdir(self.core_dir)
            
            result = subprocess.run(
                [sys.executable, "fingerprint.py"],
                text=True,
                encoding='utf-8'
            )
            
            # Return to original directory
            os.chdir(original_cwd)
            
            if result.returncode != 0:
                print(f"{Fore.RED}[!] Fingerprinting failed with return code: {result.returncode}{Style.RESET_ALL}")
                return False
            else:
                print(f"{Fore.GREEN}[+] Technology fingerprinting completed{Style.RESET_ALL}")
                return True
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error running fingerprint: {e}{Style.RESET_ALL}")
            return False
    
    def print_summary(self, open_ports, dirbuster_success, fetcher_success, fingerprint_success):
        """Print final summary"""
        print(f"\n{Fore.CYAN}=" * 4)
        print(f"{Fore.CYAN}                         ARDES SCAN SUMMARY")
        print(f"{Fore.CYAN}=" * 70)
        
        print(f"{Fore.YELLOW}Target IP:{Style.RESET_ALL} {self.target_ip}")
        print(f"{Fore.YELLOW}Open HTTP Ports:{Style.RESET_ALL} {open_ports if open_ports else 'None found'}")
        
        print(f"\n{Fore.CYAN}Pipeline Status:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Scanner: Completed")
        print(f"  {'✓' if dirbuster_success else '✗'} DirBuster: {'Completed' if dirbuster_success else 'Failed/Skipped'}")
        print(f"  {'✓' if fetcher_success else '✗'} Fetcher: {'Completed' if fetcher_success else 'Failed/Skipped'}")
        print(f"  {'✓' if fingerprint_success else '✗'} Fingerprint: {'Completed' if fingerprint_success else 'Failed/Skipped'}")
        
        # Show results locations
        print(f"\n{Fore.CYAN}Results Locations:{Style.RESET_ALL}")
        
        results_files = [
            ("Scanner Reports", os.path.join(self.reports_dir, "http_scan_*.txt")),
            ("DirBuster Reports", os.path.join(self.reports_dir, "dirb_*.txt")),
            ("Fetcher Reports", os.path.join(self.reports_dir, "fetch_*.txt")),
            ("Fingerprint Reports", os.path.join(self.reports_dir, "fingerprint_*.txt"))
        ]
        
        machine_readable_files = [
            ("Directory enumeration", os.path.join(self.results_dir, "dirb.txt")),
            ("Content analysis", os.path.join(self.results_dir, "fetch.txt")),
            ("Technology detection", os.path.join(self.results_dir, "fingerprint.txt"))
        ]
        
        print(f"  {Fore.YELLOW}Detailed Reports:{Style.RESET_ALL} {self.reports_dir}")
        for name, pattern in results_files:
            print(f"    - {name}: {pattern}")
        
        print(f"  {Fore.YELLOW}Machine Readable:{Style.RESET_ALL} {self.results_dir}")
        for name, file_path in machine_readable_files:
            exists = "✓" if os.path.exists(file_path) else "✗"
            print(f"    - {name}: {exists} {file_path}")
        
        print(f"\n{Fore.CYAN}=" * 4)
        
        if fingerprint_success:
            print(f"{Fore.GREEN}[+] ARDES scan completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Use the generated results for further analysis or exploit research{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] ARDES scan completed with some limitations{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Check individual step outputs for details{Style.RESET_ALL}")
    
    def run(self):
        """Run the complete ARDES workflow"""
        start_time = time.time()
        
        # Step 1: Run scanner
        open_ports = self.run_scanner()
        
        # Step 2: Run dirbuster for each port
        dirbuster_success = self.run_dirbuster(open_ports)
        
        # Step 3: Run fetcher
        fetcher_success = self.run_fetcher() if dirbuster_success else False
        
        # Step 4: Run fingerprint
        fingerprint_success = self.run_fingerprint() if fetcher_success else False
        
        # Calculate total time
        end_time = time.time()
        total_time = end_time - start_time
        
        # Print summary
        self.print_summary(open_ports, dirbuster_success, fetcher_success, fingerprint_success)
        
        print(f"\n{Fore.CYAN}Total scan time: {total_time:.2f} seconds{Style.RESET_ALL}")

def main():
    if len(sys.argv) != 2:
        print(f"{Fore.CYAN}ARDES - Automated Recon & Detection Suite{Style.RESET_ALL}")
        print("=" * 70)
        print(f"{Fore.YELLOW}Usage: python3 {sys.argv[0]} <IP_ADDRESS>{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: python3 {sys.argv[0]} 192.168.1.100{Style.RESET_ALL}")
        print("\nThis tool will automatically run:")
        print("  1. Scanner - Find open HTTP ports")
        print("  2. DirBuster - Enumerate directories/files")
        print("  3. Fetcher - Grab content from discovered URLs")
        print("  4. Fingerprint - Detect technologies")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    # Create orchestrator
    orchestrator = ArdesOrchestrator(target_ip)
    
    # Validate IP
    if not orchestrator.validate_ip(target_ip):
        print(f"{Fore.RED}[!] Invalid IP address: {target_ip}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Print banner
    orchestrator.print_banner()
    
    try:
        # Run the complete workflow
        orchestrator.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()