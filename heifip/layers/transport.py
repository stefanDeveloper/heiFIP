import hashlib
from typing import Type

from scapy.all import Packet, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP, UDP
from scapy.layers.tls.all import TLS

from heifip.layers.ip import IPPacket
from heifip.plugins.header import CustomTCP, CustomUDP


class TransportPacket(IPPacket):
    def __init__(self, packet: Packet, address_mapping={}, layer_map={}):
        IPPacket.__init__(self, packet, address_mapping, layer_map)
        if TCP in self.layer_map:
            self.hash = hashlib.md5(f"{self.packet[TCP].flags},{self.packet[TCP].options}".encode('utf-8')).hexdigest()
            if TLS in self.layer_map:
                self.packet[TCP].remove_payload()
            if Raw in self.layer_map and not HTTP in self.layer_map:
                self.packet[TCP].remove_payload()
        elif UDP in self.layer_map:
            self.hash = hashlib.md5(f"{self.packet[UDP].name}".encode('utf-8')).hexdigest()
            if TLS in self.layer_map:
                self.packet[UDP].remove_payload()
            if Raw in self.layer_map and not HTTP in self.layer_map:
                self.packet[UDP].remove_payload()


    def header_preprocessing(self):
        if TCP in self.layer_map:
            layer_copy = self.packet[TCP]
            layer_copy = self.header_preprocessing_tcp(layer_copy)
            if self.packet[TCP].payload != None:
                layer_copy.payload = self.packet[TCP].payload
            self.packet[TCP] = layer_copy

        if UDP in self.layer_map:
            layer_copy = self.packet[UDP]
            layer_copy = self.header_preprocessing_udp(layer_copy)
            if self.packet[UDP].payload != None:
                layer_copy.payload = self.packet[UDP].payload
            self.packet[UDP] = layer_copy

        super().header_preprocessing()

    def header_preprocessing_tcp(self, layer_copy: Packet):
        return CustomTCP(flags=layer_copy.flags, options=layer_copy.options)

    def header_preprocessing_udp(self, layer_copy: Packet):
        return CustomUDP()
