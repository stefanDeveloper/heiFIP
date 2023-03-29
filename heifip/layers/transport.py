from typing import Type

from scapy.all import Packet
from scapy.layers.inet import TCP, UDP

from heifip.layers.ip import IPPacket
from heifip.plugins.header import CustomTCP, CustomUDP


class TransportPacket(IPPacket):
    def __init__(self, packet: Packet):
        IPPacket.__init__(self, packet)

    def header_preprocessing(self):
        if self.packet.haslayer(TCP):
            layer_copy = self.packet[TCP]
            layer_copy = self.header_preprocessing_tcp(layer_copy)
            layer_copy.payload = self.packet[TCP].payload
            self.packet[TCP] = layer_copy

        if self.packet.haslayer(UDP):
            layer_copy = self.packet[UDP]
            layer_copy = self.header_preprocessing_udp(layer_copy)
            layer_copy.payload = self.packet[UDP].payload
            self.packet[UDP] = layer_copy
        super().header_preprocessing()

    def header_preprocessing_tcp(self, layer_copy: Packet):
        return CustomTCP(flags=layer_copy.flags, options=layer_copy.options)

    def header_preprocessing_udp(self, layer_copy: Packet):
        return CustomUDP()
