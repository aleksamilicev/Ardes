#!/usr/bin/env python3
import sys
import socket
import datetime
import os

# Lista portova koje proveravamo
HTTP_PORTS = [80, 8080]

def scan_ports(target_ip):
    open_ports = []
    for port in HTTP_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 sekunda timeout
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"[!] Error while scanning port {port}: {e}")
    return open_ports

def save_report(target_ip, open_ports):
    if not os.path.exists("reports"):
        os.makedirs("reports")

    today = datetime.datetime.now().strftime("%d-%m-%Y")
    filename = f"reports/scan_{today}.txt"

    with open(filename, "w") as f:
        f.write(f"Result of scanning the target {target_ip}\n")
        f.write("="*50 + "\n")
        if open_ports:
            f.write("Open HTTP ports:\n")
            for port in open_ports:
                f.write(f"- Port {port}\n")
        else:
            f.write("No open HTTP ports were found.\n")

    print(f"[+] Results are saved in {filename}")

def main():
    if len(sys.argv) != 2:
        print(f"Use case: python3 {sys.argv[0]} <IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    print(f"[*] Scanning {target_ip} for ports {HTTP_PORTS}...")

    open_ports = scan_ports(target_ip)

    if open_ports:
        print("[+] Found open ports:")
        for port in open_ports:
            print(f"   - Port {port}")
    else:
        print("[-] No open HTTP ports were found.")

    save_report(target_ip, open_ports)

if __name__ == "__main__":
    main()
