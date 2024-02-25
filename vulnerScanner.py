import requests
import nmap
import re
import socket
import concurrent.futures

def scan_ports(target, port_range='1-1024'):
    nm = nmap.PortScanner()
    nm.scan(target, port_range)
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

def scan_vulnerabilities(target):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        print("Scanning for XSS vulnerability...")
        response = requests.get('https://' + target, headers=headers, timeout=5)
        if re.search(r'<script>.*?</script>', response.text):
            print("XSS vulnerability found!")
        else:
            print("No XSS vulnerability detected.")

        print("Scanning for SQL Injection vulnerability...")
        payload = "' OR '1'='1'; --"
        response = requests.get('https://' + target + payload, headers=headers, timeout=5)
        if "error in your SQL syntax" in response.text:
            print("SQL Injection vulnerability found!")
        else:
            print("No SQL Injection vulnerability detected.")

        print("Scanning for Local File Inclusion vulnerability...")
        payload = "../../../../../../../../etc/passwd"
        response = requests.get('https://' + target + payload, headers=headers, timeout=5)
        if "root:x:" in response.text:
            print("Local File Inclusion vulnerability found!")
        else:
            print("No Local File Inclusion vulnerability detected.")

    except requests.exceptions.RequestException as e:
        print(f"Error scanning vulnerabilities: {e}")

def scan_all(target):
    try:
        ip = target if re.match(r'\d+\.\d+\.\d+\.\d+', target) else socket.gethostbyname(target)
        print(f"Scanning target: {target} (IP: {ip})")

        # Multithreaded port scanning
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(scan_ports, ip)
            future.result()

        # Scanning for vulnerabilities
        scan_vulnerabilities(target)

    except (socket.error, concurrent.futures.CancelledError) as e:
        print(f"Error scanning: {e}")

    input("Press Enter to exit...")

if __name__ == "__main__":
    target = input('Target URL without https or http: ')
    scan_all(target)
