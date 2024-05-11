#requirements
#sudo apt install net-tools

#modules
import fcntl
import os
import random
import re
import socket
import struct
import subprocess



def change_mac(interface, new_mac):
  try:
    # Bring down the network interface
    subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
    # Change the MAC address
    subprocess.run(['sudo','ifconfig', interface, 'hw', 'ether', new_mac],
                   check=True)
     # Bring up the network interface
    subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
    return True
  except subprocess.SubprocessError as e:
    print(f"Failed to change MAC address: {str(e)}")
    return False


def my_mac(interface):
  try:
    # Create a socket object to extract the MAC address of a specified interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(interface[:15], 'utf-8')))
    s.close()
    # Extract and format the MAC address from response
    return ':'.join(['%02x' % b for b in info[18:24]])
  except Exception as e:
    return f"Error retrieviing MAC address: {str(e)}"
  
def rand_mac():
  return":".join([('0'+hex(random.randint(0,255))[2:])[-2:].upper() for _ in range(6)])

def custom_mac():
  mac_address = input('\nPlease enter a MAC address: \n(ex:01:23:45:67:89:AB):  ')
  if re.match('(?=[a-f0-9]{2}:){5}[a-f0-9]{2}', mac_address):
    return mac_address.upper()
  else:
      print('Invalid MAC address format.')

def menu(interface):
  current_mac = my_mac(interface)
  while True:
    print(f'Current MAC address: {current_mac}\n')
    choice = input('1) Generate a random MAC address: \n2) Enter the MAC address you wish to clone: \n')

    if choice == '1':
      new_mac = rand_mac()
      print('New MAC address: {new_mac}')
      if change_mac(interface, new_mac):
        print('MAC address successfully changed to : {new_mac}.')
      else:
        print('Failed to change MAC address.')

    elif choice == '2':
      print('Current MAC address: {new_mac}\n')
      new_mac = custom_mac()
      print('New MAC address: {new_mac}')
      if change_mac(interface, new_mac):
        print('MAC address successfully changed to : {new_mac}.')
      else:
        print('Failed to change MAC address.')

    else:
      print('Please enter a valid option.\n')

    return
   
def main():
  interface_name = input('Enter the name of your interface: ')
  menu(interface_name)

if __name__ == '__main__':
  main()
