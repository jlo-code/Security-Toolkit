from scapy.all import sr1, IP, TCP
import sys
import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse
import subprocess
import random
import re

# Function to retrieve the current MAC address of an interface
def get_current_mac(interface):
    try:
        result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
        mac_address = re.search(r"ether ([\da-fA-F:]+)", result.stdout).group(1)
        return mac_address
    except Exception as e:
        print(f"Error retrieving current MAC address: {e}")
        return None

# Function to change MAC address to a random one
def change_mac(interface):
    original_mac = get_current_mac(interface)
    if original_mac:
        print(f"Original MAC address: {original_mac}")

    # Generate a random MAC address
    new_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0x00, 0x7F),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
    )

    print(f"Changing MAC address to: {new_mac}")
    try:
        subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
        subprocess.run(['sudo', 'ifconfig', interface, 'hw', 'ether', new_mac], check=True)
        subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
        print(f"MAC address successfully changed to {new_mac}")
    except Exception as e:
        print(f"Error changing MAC address: {e}")
        return None

    return original_mac  # Return original MAC for later restoration

# Function to restore the original MAC address
def restore_mac(interface, original_mac):
    if original_mac:
        print(f"Restoring MAC address to: {original_mac}")
        try:
            subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
            subprocess.run(['sudo', 'ifconfig', interface, 'hw', 'ether', original_mac], check=True)
            subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
            print(f"MAC address successfully restored to {original_mac}")
        except Exception as e:
            print(f"Error restoring MAC address: {e}")

# Port Scanning function using scapy
def scan_target(target_ip, port_range=(1, 1024)):
    print(f"Scanning target {target_ip} for open ports in range {port_range[0]}-{port_range[1]}...\n")

    open_ports = []

    for port in range(port_range[0], port_range[1] + 1):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")  # SYN flag
        response = sr1(pkt, timeout=1, verbose=0)

        if response:
            if response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK (open port)
                print(f"Port {port} is open.")
                open_ports.append(port)
            # Send RST to gracefully close the connection
            sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
        else:
            # No response could indicate a filtered or closed port
            pass

    print("\nScan complete.")
    return open_ports

# Function to gather web application information using HTTP headers
def get_web_app_info(target_ip):
    target_urls = [f"http://{target_ip}", f"https://{target_ip}"]

    for url in target_urls:
        try:
            print(f"\nAttempting to get web app info from: {url}")
            response = requests.get(url, timeout=3)
            parsed_url = urlparse(url)

            # Print headers for analysis
            print(f"\nHeaders for {url}:")
            for key, value in response.headers.items():
                print(f"{key}: {value}")

            # Example of pulling specific web details:
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Unknown')

            print(f"\nDetected web server: {server}")
            print(f"Powered by: {powered_by}")

            # Check for common CMS or web frameworks in the content
            content = response.text.lower()
            if 'wordpress' in content:
                print("Web application detected: WordPress")
            elif 'drupal' in content:
                print("Web application detected: Drupal")
            elif 'joomla' in content:
                print("Web application detected: Joomla")
            else:
                print("No specific web application detected.")

            break  # Exit after a successful response

        except RequestException as e:
            print(f"Could not retrieve information from {url}: {e}")

# Detect Intrusion Prevention System (IPS)
def detect_ips(target_ip, port):
    packet_count = 0
    print(f"Sending packets to detect IPS on {target_ip}:{port}...")
    for _ in range(10):  # Sending 10 packets
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            print(f"No response for packet {packet_count}")
        else:
            print(f"Response received for packet {packet_count}")
        
        packet_count += 1

# Menu to navigate the program
def menu():
    while True:
        print("\n--- Network Security Information Tool ---")
        print("1. Temporarily mask MAC address and scan target for open ports")
        print("2. Get web application information")
        print("3. Detect Intrusion Prevention System (IPS)")
        print("4. Exit")
        
        choice = input("Select an option (1-4): ")

        if choice == '1':
            target_ip = input("Enter target IP address: ")
            port_range_start = input("Enter start of port range (default 1): ") or '1'
            port_range_end = input("Enter end of port range (default 1024): ") or '1024'

            interface = input("Enter your network interface (e.g., eth0, wlan0): ")
            original_mac = change_mac(interface)  # Temporarily change MAC address
            open_ports = scan_target(target_ip, (int(port_range_start), int(port_range_end)))

            # Restore the original MAC address after the scan
            restore_mac(interface, original_mac)

        elif choice == '2':
            target_ip = input("Enter target IP address: ")
            open_ports = scan_target(target_ip)
            if 80 in open_ports or 443 in open_ports:
                get_web_app_info(target_ip)
            else:
                print("\nNo HTTP/HTTPS ports detected. Skipping web app information retrieval.")
        elif choice == '3':
            target_ip = input("Enter target IP address: ")
            port = input("Enter target port (e.g., 80): ")
            detect_ips(target_ip, int(port))
        elif choice == '4':
            print("Exiting the program.")
            sys.exit(0)
        else:
            print("Invalid option. Please select again.")

# Main function
if __name__ == "__main__":
    menu()
