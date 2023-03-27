from .ip import IPPacket
from heifip.plugins.header import CustomTCP, CustomUDP
from scapy.all import Packet
from scapy.layers.inet import TCP, UDP
from typing import Type


class TransportPacket(IPPacket):
    def __init__(self, packet: Packet):
        IPPacket.__init__(self, packet)

    def header_preprocessing_tcp(self, packet: Packet, layer_class: Type[Packet]):
        layer_copy = packet[layer_class]
        return CustomTCP(flags=layer_copy.flags, options=layer_copy.options)

    def header_preprocessing_udp(self, packet: Packet, layer_class: Type[Packet]):
        layer_copy = packet[layer_class]
        return CustomUDP()
