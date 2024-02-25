import requests
import nmap
import re
import socket

# Function to scan the website for server information, XSS, SQL Injection, and LFI
def scan_all(target):
    try:
        # If the target is an IP address, use it directly; otherwise, resolve the URL to an IP
        ip = target if re.match(r'\d+\.\d+\.\d+\.\d+', target) else socket.gethostbyname(target)
        print(f"Scanning target: {target} (IP: {ip})")

        # Scan server using Nmap
        print("Scanning for open ports using Nmap...")
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024')
        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print(f'Host : {host} ({nm[host].hostname()})')
            print('State : {}'.format(nm[host].state()))
            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                ports = nm[host][proto].keys()
                for port in ports:
                    print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

        # Scan for XSS vulnerability
        print("Scanning for XSS vulnerability...")
        response = requests.get('https://' + target, timeout=5)
        if re.search(r'<script>.*?</script>', response.text):
            print("XSS vulnerability found!")
        else:
            print("No XSS vulnerability detected.")

        # Scan for SQL Injection vulnerability
        print("Scanning for SQL Injection vulnerability...")
        payload = "' OR '1'='1'; --"
        response = requests.get('https://' + target + payload, timeout=5)
        if "error in your SQL syntax" in response.text:
            print("SQL Injection vulnerability found!")
        else:
            print("No SQL Injection vulnerability detected.")

        # Scan for Local File Inclusion vulnerability
        print("Scanning for Local File Inclusion vulnerability...")
        payload = "../../../../../../../../etc/passwd"
        response = requests.get('https://' + target + payload, timeout=5)
        if "root:x:" in response.text:
            print("Local File Inclusion vulnerability found!")
        else:
            print("No Local File Inclusion vulnerability detected.")

    except (requests.exceptions.RequestException, socket.error) as e:
        print(f"Error scanning: {e}")

target = input('Target url without https or http :')  # Replace with your target
scan_all(target)

input("Press Enter to exit...")
