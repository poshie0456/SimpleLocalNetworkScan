##THE FOLLOWING PROJECT NEEDS TO BE RUN AS ROOT
import scapy.all as scapy
import socket

def getDeviceName(ipaddr):
    try:
        hostname, _, _ = socket.gethostbyaddr(ipaddr)
        return hostname
    except:
        return "Not Found"
    
def scan(ip):   
    # Create ARP request packet
    arp_req = scapy.ARP(pdst=ip)        
    # Create Ethernet frame with broadcast address
    bcAddr = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Sending a send/receive ARP packet
    answered_list = scapy.srp(bcAddr/arp_req, timeout=2, verbose=False)[0]

    # Get and print the IP and MAC addresses from the response
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc,"hostName": getDeviceName(element[1].psrc)}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("\n\nRUN AS ROOT\n\n\nResults:\n\nIP Address\t\tMAC Address\t\tHostName")
    print("----------------------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t" + client["hostName"])

# Ip range to scan, works on basis of 255.255.255.0
ip_range = "192.168.1.1/24"

scan_result = scan(ip_range)
print_result(scan_result)
