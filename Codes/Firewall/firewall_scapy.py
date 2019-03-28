#Program to build a mini firewall using python

import struct
import sys
import time
import socket
from socket import AF_INET, AF_INET6, inet_ntoa
from scapy.all import *
from netfilterqueue import NetfilterQueue
# from packets import IPPacket, TCPPacket, to_tuple

#from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from math import ceil
import re
import binascii


_NFQ_INIT = 'iptables -I INPUT -j NFQUEUE --queue-num %d'
_NFQ_CLOSE = 'iptables -D INPUT -j NFQUEUE --queue-num %d'



global action, inputprotocol, actiontype, inputportnum, inputipaddr

class Firewall:
    def __init__(self):
        self.protocolname = ''
        self.srcipaddress = ''
        self.srcportnum = 0

    def valid_IP_address(self, ext_addr):
        try:
           socket.inet_ntoa(ext_addr)
           return True
        except socket.error:
           return False

    def obtain_fields(self, pckt):
        try:
            protocol = struct.unpack('!B', pckt[9:10]) # (integer,)
            total_length = struct.unpack('!H', pckt[2:4])
            return self.strip_format(protocol), self.strip_format(total_length)
        except struct.error as e:
            print(e)
            return None, None

    def valid_ip_header(self, pckt):
        try:
            #print(pckt)
            ip_header = struct.unpack('!B', pckt[0:1])
            return self.strip_format(ip_header)
        except struct.error as e:
            print(e)
            print(pckt[0:1])
            return None

    def get_udp_length(self, pckt, startIndex):
        try:
            length = struct.unpack('!H', pckt[startIndex + 4 : startIndex + 6])
            return self.strip_format(length)
        except struct.error:
            return None

    def protocol_selector(self, protocol):
        if (protocol == 1):
            return "icmp"
        elif (protocol == 6):
            return 'tcp'
        elif (protocol == 17):
            return 'udp'
        return None

    def check_protocol(self, protocol):
        return (protocol == 'tcp') or (protocol == 'udp') or (protocol == 'icmp')

    def within_range(self, start_port, end_port, external_ip):
        return external_ip >= start_port and external_ip <= end_port

    def is_IP_Prefix(self, data):
        return data.find('/')

    def strip_format(self, format_str):
        new_str = str(format_str)
        return int(new_str[1: len(new_str) - 2])

        #""" Returns the external port and checks to see if there is a socket error. If
            #the port is valid, then it returns a number, else it returns 'None'. """

    def handle_external_port(self, pckt, startIndex):
        try:
            ext_port = pckt[startIndex: startIndex + 2]
            ext_port = struct.unpack('!H', ext_port)
            return ext_port
        except struct.error:
            return None

        #""" Returns the TYPE field for the IMCP packet."""

    def handle_icmp_packet(self, pckt, startIndex):
        try:
            type_field = pckt[startIndex: startIndex + 1]
            type_field = struct.unpack('!B', type_field)
            return self.strip_format(type_field)
        except struct.error:
            return None

        #""" Returns the direction of the packet in a string."""

    def packet_direction(self, direction):
        if (direction == 'outgoing'):
            return 'outgoing'
        else:
            return 'incoming'


            # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pckt_dir, pckt):
        ip_header = self.valid_ip_header(pckt)
        if (ip_header == None):
            print(1)
            return
        ip_header = ip_header & 0x0f
        if (ip_header < 5):
            print(2)
            return

        protocol, total_length = self.obtain_fields(pckt)
        if (protocol == None and total_length == None):
            print(3)
            return

        if (total_length != len(pckt)):
            print(4)
            return

        if (self.protocol_selector(protocol) == None):
            #self.send_packet(pckt, pckt_dir)
            print(5)
            return

        src_addr, dst_addr, pckt_dir = pckt[12:16], pckt[16:20], self.packet_direction(pckt_dir)
        if (pckt_dir == 'incoming'):
            external_addr = src_addr
        else:
            external_addr = dst_addr
        if not (self.valid_IP_address(external_addr)): # check valid address.
            print(6)
            return

        if (protocol == 6): # TCP
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
            else:
                external_port = self.handle_external_port(pckt, ((ip_header) * 4) + 2)
            if (external_port == None): # drop packet due to port socket error.
                print(7)
                return

        elif (protocol == 1): # ICMP
            type_field = self.handle_icmp_packet(pckt, (ip_header * 4))
            if (type_field == None):
                print(8)
                return

        elif (protocol == 17): # UDP
            udp_length = self.get_udp_length(pckt, (ip_header * 4))
            if (udp_length == None or udp_length < 8):
                print(9)
                return
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
                if (external_port == None):
                    print(10)
                    return

        verdict = "pass"
        self.protocolname = self.protocol_selector(protocol)
        self.srcipaddress = external_addr
        if (protocol != 1):
            self.srcportnum = external_port


def cb(p):
    data = p.get_payload()
    pkt = IP(data)

    f = Firewall()
    f.handle_packet("incoming", str(pkt))
    print(f.protocolname)
    print(socket.inet_ntoa(f.srcipaddress))
    print(f.srcportnum)

    if action == "block":
        if actiontype == "protocol":

            if inputprotocol == f.protocolname:  #TCP, UDP, ICMP
                p.drop()
                print(f.protocolname + " Packet blocked")

        elif actiontype == "ipaddress":

            if inputipaddr == socket.inet_ntoa(f.srcipaddress):  #IP address
                p.drop()
                print(socket.inet_ntoa(f.srcipaddress) + " blocked")

        elif actiontype == "portnum":
            if int(inputportnum) in f.srcportnum:
                p.drop()
                print(inputportnum + " blocked")

    elif action == "accept":
        p.accept()
        print("Packet accepted")

    else:
        p.accept()
        print("Packet accepted")


global action, inputprotocol, actiontype, inputportnum, inputipaddr

actiontype = "ipaddress"
action = "block"
inputportnum = 20
inputipaddr =  "202.137.235.12"
qnum = 1
setup = _NFQ_INIT % qnum
os.system(setup)
print("Setting up IPTables: " + setup)
print("Initializing NetfilterQueue...")
nfq = NetfilterQueue()
print("Binding...")
nfq.bind(qnum, cb)

try:
    nfq.run()
    print("Running")
except KeyboardInterrupt:
    print("Interrupted")

print ("Unbinding...")
nfq.unbind()
teardown = _NFQ_CLOSE % qnum
os.system(teardown)
print('\nTore down IPTables: ' + teardown)
print ("Quitting Firewall")