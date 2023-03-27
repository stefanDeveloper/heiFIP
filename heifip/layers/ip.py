from .packet import FIPPacket
from heifip.plugins.header import CustomIP, CustomIPv6
from scapy.all import Packet, RandIP6, RandIP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from typing import Type


class IPPacket(FIPPacket):
    def __init__(self, packet: Packet):
        FIPPacket.__init__(self, packet)
        if packet.haslayer(IP):
            self.__filter_ipv4(packet)
        elif packet.haslayer(IPv6):
            self.__filter_ipv6(packet)

    def __filter_ipv4(self, packet: Packet):
        previous_src = packet[IP].src
        previous_dst = packet[IP].dst

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

        packet[IP].src = new_src
        packet[IP].dst = new_dst

    def header_preprocessing_ipv4(self, packet: Packet, layer_class: Type[Packet]):
        layer_copy = packet[layer_class]
        return CustomIP(
            version=layer_copy.version,
            tos=layer_copy.tos,
            ttl=layer_copy.ttl,
            flags=layer_copy.flags,
            proto=layer_copy.proto,
        )

    def __filter_ipv6(self, packet: Packet):
        previous_src = packet[IPv6].src
        previous_dst = packet[IPv6].dst

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

        packet[IPv6].src = new_src
        packet[IPv6].dst = new_dst

    def header_preprocessing_ipv6(self, packet: Packet, layer_class: Type[Packet]):
        layer_copy = packet[layer_class]
        return CustomIPv6(
            version=layer_copy.version,
            tc=layer_copy.tc,
            nh=layer_copy.nh,
            hlim=layer_copy.hlim,
        )
