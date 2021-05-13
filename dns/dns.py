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
A = 1
PTR = 12
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



class dns(object):
    def __init__(self, host_file, dns_address, remote_addr, port):
        self.dns_address = dns_address
        self.remote_address = remote_addr
        self.port = port
        self.host_file = host_file
    def start(self):
        # first establish socket and bind with localhost, create a thread to handle query to Google DNS server:
        print("DNS server is running...")
        self.pi_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.pi_dns.bind((self.dns_address, self.port))
        # forward all requests for now 
        while True:
            respondet, addr = self.pi_dns.recvfrom(1024)
            self.dns_thread = threading.Thread(target=self.__handle_request, args=(respondet, addr, self.remote_address, self.port,))
            self.dns_thread.daemon = True
            self.dns_thread.start()
    
    def __handle_request(self, pkt, addr, remote_addr, remote_port):
        # forward pkt to remote dns server and relay back response to addr
        # check domain name by deserialize respondet 
        # if metrics.fresno.cs158b => return list of pi domain, qtype = 33
        # if ip 172.16.6.11-20 => return single result
        # else forward to remote dns
        packet = Deserialize(pkt, {
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
                'address': ('4B', serializeme.IPv4),
            }
        })
        # cut off pid, qname, qtype, qclass because of API bugs
        header = Serialize({
            # 'pid': ('2B', packet.get_field('pid').value),
            'QR': ('1b', 1),
            'OPCODE': ('4b', 0),
            'AA': ('1b', 0),
            'TC': ('1b', 0),
            'RD': ('1b', 1),
            'RA': ('1b', 1),
            'Z': ('3b', 0),
            'RCODE': ('4b', 0),
            'qcnt': ('2B', 1),
            'acnt': ('2B', 1),
            'ncnt': ('2B', 0),
            'mcnt': ('2B', 1)
            # 'qname': (serializeme.PREFIX_LEN_NULL_TERM, qname),
            # 'qtype': ('2B', 1),
            # 'qclass': ('2B', 1)
        })
        domain_pattern = "pi(1[1-9]|20)+\.fresno\.cs158b"
        ip_pattern = "(1[1-9]|20)\.6\.16\.172\.in-addr\.arpa"
        qname = packet.get_field('qname').value
        if (re.search(domain_pattern, qname)):
            print("Domain within the city: {}".format(qname))
            ip_value = "172.16.6." + qname[2:4]
            # construct a response packet with ip_value in it 
            qname_list = packet.get_field('qname').value.split(".")
            # print('qname: {} '.format(qname))
            qname_encoded = b''
            for subname in qname_list:
                qname_encoded += bytes([len(subname)]) + subname.encode()
            question_encoded = qname_encoded + b'\x00\x00\x01\x00\x01'
            response = pkt[0:2] + header.packetize() + question_encoded + self.__record_to_bytes(qname, A, 400, ip_value)
            # print(response)
            self.pi_dns.sendto(response, addr)
        elif (re.search(ip_pattern, qname)):
            print("IP within the city: {}".format(qname))
            qname_list = qname.split(".")
            port = qname_list[0]
            domain_record = 'pi' + str(port) + '.fresno.cs158b'
            # construct header, question, and result to send back
            qname_encoded = b''
            for subname in qname_list:
                qname_encoded += bytes([len(subname)]) + subname.encode()
            question_encoded = qname_encoded + b'\0\0\x0c\0\1'
            # calculate the length for the domain name: total_length + 2 
            response = pkt[0:2] + header.packetize() + question_encoded + self.__record_to_bytes(qname, PTR, 400, domain_record)
            self.pi_dns.sendto(response, addr)
        else: # send request to 8.8.8.8 and forward the reply s
            remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            remote.connect((remote_addr, remote_port))
            remote.send(pkt)
            resData, resAddr = remote.recvfrom(1024)
            # print(resData)
            respond = Deserialize(resData, {
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
                    'address': ('4B', serializeme.IPv4),
                }
            })
            self.pi_dns.sendto(resData, addr)

    def __record_to_bytes(self, domain_name, record_type, ttl, ip):
        resp = b"\xc0\x0c"
        # query type A or PTR
        if record_type == A:
            resp += b"\x00\x01"
        elif record_type == PTR:
            resp += b"\x00\x0c"
        resp += b"\x00\x01"    # class IN
        resp += int(ttl).to_bytes(4, byteorder="big")    # ttl in bytes
        # IP length or domain length with the ip/domain value
        if record_type == A:
            resp += b"\x00\x04"    
            for part in ip.split("."):
                resp += bytes([int(part)])
        elif record_type == PTR:
            domain_length = len(ip) + 2
            # print("Domain length: {} in bytes: {}".format(domain_length, bytes([domain_length])))
            resp += b"\x00" + bytes([domain_length])
            domain_name = b''
            for subname in ip.split("."):
                domain_name += bytes([len(subname)]) + subname.encode()
            resp = resp + domain_name + b'\00'
        return resp

    def handle_srv(self, deserialized):
        # handle dns type 33 requests
        target = deserialized.get_field("qname")
        if target != "metrics.fresno.cs158b":
            pass


if __name__ == "__main__":
    dns = dns("hosts.csv", DNS_IP, GOOGLE_DNS, DNS_PORT)
    dns.start()