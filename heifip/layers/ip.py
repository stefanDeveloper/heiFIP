from typing import Type

from scapy.all import Packet, RandIP, RandIP6
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from heifip.layers.packet import FIPPacket
from heifip.plugins.header import CustomIP, CustomIPv6


class IPPacket(FIPPacket):
    def __init__(self, packet: Packet):
        FIPPacket.__init__(self, packet)
        if self.packet.haslayer(IP):
            self.__filter_ipv4()
        elif packet.haslayer(IPv6):
            self.__filter_ipv6()

    def __filter_ipv4(self):
        previous_src = self.packet[IP].src
        previous_dst = self.packet[IP].dst

        if previous_src in self.address_mapping:
            new_src = self.address_mapping[previous_src]
        else:
            new_src = RandIP()._fix()
            self.address_mapping[previous_src] = new_src

        if previous_dst in self.address_mapping:
            new_dst = self.address_mapping[previous_dst]
        else:
            new_dst = RandIP()._fix()
            self.address_mapping[previous_dst] = new_dst

        self.packet[IP].src = new_src
        self.packet[IP].dst = new_dst

    def header_preprocessing(self):        
        if self.packet.haslayer(IP):
            layer_copy = self.packet[IP]
            layer_copy = self.header_preprocessing_ipv4(layer_copy)
            layer_copy.payload = self.packet[IP].payload
            self.packet[IP] = layer_copy
        if self.packet.haslayer(IPv6):
            layer_copy = self.packet[IPv6]
            layer_copy = self.header_preprocessing_ipv6(layer_copy)
            layer_copy.payload = self.packet[IPv6].payload
            self.packet[IPv6] = layer_copy

        super().header_preprocessing()

    def header_preprocessing_ipv4(self, layer_copy: Packet):
        return CustomIP(
            version=layer_copy.version,
            tos=layer_copy.tos,
            ttl=layer_copy.ttl,
            flags=layer_copy.flags,
            proto=layer_copy.proto,
        )

    def __filter_ipv6(self):
        previous_src = self.packet[IPv6].src
        previous_dst = self.packet[IPv6].dst

        if previous_src in self.address_mapping:
            new_src = self.address_mapping[previous_src]
        else:
            new_src = RandIP6()._fix()
            self.address_mapping[previous_src] = new_src

        if previous_dst in self.address_mapping:
            new_dst = self.address_mapping[previous_dst]
        else:
            new_dst = RandIP6()._fix()
            self.address_mapping[previous_dst] = new_dst

        self.packet[IPv6].src = new_src
        self.packet[IPv6].dst = new_dst

    def header_preprocessing_ipv6(self, layer_copy: Packet):
        return CustomIPv6(
            version=layer_copy.version,
            tc=layer_copy.tc,
            nh=layer_copy.nh,
            hlim=layer_copy.hlim,
        )
