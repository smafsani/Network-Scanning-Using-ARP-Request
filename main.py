import scapy.all as scapy

# request = scapy.ARP()
# print(request.show())
# print(scapy.ls(request))

def scan(pdst):
    request = scapy.ARP(pdst=pdst)
    broadcast_dest = "ff:ff:ff:ff:ff:ff"
    broadcast_packet = scapy.Ether(dst = broadcast_dest)

    combined_packet = broadcast_packet/request
    clients = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    clients_list = []
    for client in clients:
        client_dict = {"ip" : client[1].psrc, "mac" : client[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results):
    print("IP\t\t\t\tMAC\n---------------------------------")
    for client in results:
        print("{:16}{}".format(client['ip'], client['mac']))

input = input("Enter target IP or IP range (such as 192.168.0.1/24):\n")
# "192.168.0.1/24"
results = scan(input)
print_result(results)
