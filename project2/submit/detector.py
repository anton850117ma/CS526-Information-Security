import dpkt
import socket
import sys

def main():

    # open the file
    f = open(sys.argv[1], 'rb')
    pcap = dpkt.pcap.Reader(f)
    dict = {}

    # loop every packet
    for ts, buf in pcap:
        
        # if the packet is valid
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue
        
        # if it is a IP packet
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data

        # if its protocol is TCP
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data

        # get source address and destination address
        src_str = socket.inet_ntoa(ip.src)
        dst_str = socket.inet_ntoa(ip.dst)

        # if the address is new to my dictionary
        if dict.get(dst_str) == None:
            dict[dst_str] = (0,0)
        if dict.get(src_str) == None:
            dict[src_str] = (0,0)

        # calculate times of SYN packets (to source) and SYN+ACK packets (to destination)
        if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
            send, receive = dict.get(dst_str)
            dict[dst_str] = (send, receive+1)
        elif tcp.flags & dpkt.tcp.TH_SYN:
            send, receive = dict.get(src_str)
            dict[src_str] = (send+1, receive)
    
    # pick addresses that meet our requirement
    for key, values in dict.items():
        if values[0] > 3*values[1]:
            print key

    f.close()

if __name__ == "__main__":
    main()