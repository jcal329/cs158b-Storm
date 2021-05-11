# We will have to handle the request from DIG
# resolve hostname: for example: 172.16.6.11 => pi11.fresno.cs158b [172.16.6.xx] where xx: 11-20
# resolve ip address: for example: pixx.fresno.cs158b => 172.16.6.xx
# after handle the request, we have to reply back to DIG the result that follow DNS reply protocol
# for ip address not within our range: => not found???
# for hostname not end within dns_name: fresno.cs158b => request 8.8.8.8 for the result and relay back the result to DIG
# for hostname with corrected domain name but invalid port nunber => not found


# for SRV records: metrics.fresno.cs158b resolve SRV records for each pi on port 9100
# for node exporter: https://github.com/prometheus/node_exporter
# dig SRV metrics.athens.cs158b to test

import socket
import serializeme
from serializeme import Deserialize, Serialize
import threading
import re

DNS_IP = "127.0.0.1"
GOOGLE_DNS = "8.8.8.8"
DNS_PORT = 53
DOMAIN_NAME = "fresno.cs158b"
DNS_REQ = {
    "id": "2B",
    "qr": "1b",
    "opcode": "4b",
    "aa": "1b",
    "tc": "1b",
    "rd": "1b",
    "ra": "1b",
    "z": "3b",
    "rcode": "4b",
    "qdcount": "2B",
    "ancount": "2B",
    "nscount": "2B",
    "arcount": "2B",
    "qname": serializeme.PREFIX_LEN_NULL_TERM,
    "qtype": "2B",
    "qclass": "2B"
}

DNS_RR = {
    'pid': ('2B'),
    'pflags': ('2B'),
    'qcnt': ('2B'),
    'acnt': ('2B', '', 'ANSWERS'),
    'ncnt': ('2B'),
    'mcnt': ('2B'),
    'qname': (serializeme.NULL_TERMINATE, serializeme.HOST),
    'qtype': ('2B'),
    'qclass': ('2B'),
    'ANSWERS': {
        'name': ('2B'),
        'type': ('2B'),
        'class': ('2B'),
        'ttl': ('4B'),
        'data_length': ('2B'),
        'address': ('4B', serializeme.IPv4)
    }
}



class DNS_PI(object):

    def __init__(self, host_file, dns_address, remote_addr, port):
        self.dns_address = dns_address
        self.remote_address = remote_addr
        self.port = port
        self.host_file = host_file

    def start(self):
        # first establish socket and bind with localhost, create a thread to handle query to Google DNS server:
        self.pi_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.pi_dns.bind((self.dns_address, self.port))
        # forward all requests for now
        while True:
            packet, addr = self.pi_dns.recvfrom(1024)
            self.dns_thread = threading.Thread(target=self.__handle_request,
                                               args=(packet, addr, self.remote_address, self.port,))
            self.dns_thread.daemon = True
            self.dns_thread.start()

    def __handle_request(self, pkt, addr, remote_addr, remote_port):
        # forward pkt to remote dns server and relay back response to addr
        dns_pkt = Deserialize(pkt, DNS_REQ)
        req_type = dns_pkt.get_field("qtype")
        qname = dns_pkt.get_field("qname")
        # check query type, if srv run handle_srv()

        if req_type == 33:
            self.handle_srv(dns_pkt)
        elif req_type == 1:
            # if IP request, check against IPs in host.csv and return pXX.fresno.cs158b if it exists
            # otherwise pass to google server

        remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        remote.connect((remote_addr, remote_port))
        remote.send(pkt)
        resData, resAddr = remote.recvfrom(1024)
        self.pi_dns.sendto(resData, addr)

    def handle_srv(self, deserialized):
        # handle dns type 33 requests
        target = deserialized.get_field("qname")
        if target != "metrics.fresno.cs158b":

if __name__ == "__main__":
    dns = DNS_PI("hosts.csv", DNS_IP, GOOGLE_DNS, DNS_PORT)
    dns.start()