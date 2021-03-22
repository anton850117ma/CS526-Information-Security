import dpkt
import socket
import sys

def main():

    # open the file
    f = open(sys.argv[1])
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
        # if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        #     continue
        ip = eth.data

        # if its protocol is TCP
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data
        
        # get source address and destination address
        src_str = socket.inet_ntoa(ip.src)
        # print "gg"
        # if the address is new to my dictionary
        if dict.get(src_str) == None:
            dict[src_str] = (0,0,0)

        # calculate times of SYN packets (to source) and SYN+ACK packets (to destination)
        if (tcp.flags & dpkt.tcp.TH_SYN):
            times, max_seq, min_seq = dict.get(src_str)
            dict[src_str] = (times+1, max(max_seq, tcp.seq), min(min_seq, tcp.seq))
        
    
    # pick addresses that meet our requirement
    max_diff = 0
    max_ip = []

    for key, values in dict.items():
        if values[0] > 5 and max_diff <= values[1] - values[2]:
            max_diff = values[1] - values[2]
            max_ip.append(key)
    
    for ip in max_ip:
        print ip

    f.close()

if __name__ == "__main__":
    main()