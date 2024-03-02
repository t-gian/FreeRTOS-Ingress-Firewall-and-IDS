import socket
import struct
import dpkt
import re

def get_initial_ip(ip_int):
    oct_arr = [(ip_int >> 24) & 255, (ip_int >> 16) & 255, (ip_int >> 8) & 255, ip_int & 255]
    oct_arr.reverse()
    ip_str = ".".join(map(str, oct_arr))
    return ip_str

def get_initial_port(port_int):
    port_int = int(port_int)
    port_int = ((port_int & 0xFF) << 8) | ((port_int >> 8) & 0xFF)
    return port_int

with open('../PART_3/out.log', 'r') as file:
    with open('./output.pcap', 'wb') as pcap_file:
        
        pcap_writer = dpkt.pcap.Writer(pcap_file)
        for line in file:
            
            if line.startswith('#PCAP'):
                # Extract the relevant information using regular expressions
                match = re.match(r'#PCAP (\d+) (\d+) (\d+) (\d+) (\d+)', line)
                if match:
                    source_ip = get_initial_ip(int(match.group(1)))
                    destination_ip = get_initial_ip(int(match.group(2)))
                    source_port = get_initial_port(int(match.group(4)))
                    destination_port = get_initial_port(int(match.group(5)))
                    protocol = int(match.group(3))

                    eth = dpkt.ethernet.Ethernet()

                    if protocol == 6:
                        tcp = dpkt.tcp.TCP()
                        tcp.sport = source_port
                        tcp.dport = destination_port
                        tcp.data = b'TCP packet'
                        ip = dpkt.ip.IP(src=socket.inet_aton(source_ip), dst=socket.inet_aton(destination_ip), p=dpkt.ip.IP_PROTO_TCP)
                        ip.data = tcp
                        eth.data = ip
                    elif protocol == 17:
                        udp = dpkt.udp.UDP()
                        udp.sport = source_port
                        udp.dport = destination_port
                        udp.data = b'UDP packet'
                        ip = dpkt.ip.IP(src=socket.inet_aton(source_ip), dst=socket.inet_aton(destination_ip), p=dpkt.ip.IP_PROTO_UDP)
                        ip.data = udp
                        eth.data = ip
                    elif protocol == 1:
                        # Create an ICMP packet
                        icmp = dpkt.icmp.ICMP()
                        icmp.type = dpkt.icmp.ICMP_ECHO
                        icmp.data = b'ICMP packet'
                        ip = dpkt.ip.IP(src=socket.inet_aton(source_ip), dst=socket.inet_aton(destination_ip), p=dpkt.ip.IP_PROTO_ICMP)
                        ip.data = icmp
                        eth.data = ip
                    else:
                        ip = dpkt.ip.IP(src=socket.inet_aton(source_ip), dst=socket.inet_aton(destination_ip))
                        eth.data = ip

                    pcap_writer.writepkt(eth)

# Print a message to indicate the completion of the task
print('Packets written to output.pcap file.')
