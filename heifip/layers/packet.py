from scapy.all import Packet, RandMAC
from scapy.layers.inet import Ether


class UnknownPacket:
    def __init__(self, packet, address_mapping={}):
        self.address_mapping = address_mapping
        self.packet = packet

class FIPPacket:
    def __init__(self, packet, address_mapping={}):
        self.address_mapping = address_mapping
        self.packet = packet
        if packet.haslayer(Ether):
            self.__filter(packet)


    def __filter(self, packet):
        previous_src = packet[Ether].src
        previous_dst = packet[Ether].dst

        if previous_src in self.address_mapping:
            new_src = self.address_mapping[previous_src]
        else:
            new_src = RandMAC()._fix()
            self.address_mapping[previous_src] = new_src

        if previous_dst in self.address_mapping:
            new_dst = self.address_mapping[previous_dst]
        else:
            new_dst = RandMAC()._fix()
            self.address_mapping[previous_dst] = new_dst

        packet[Ether].src = new_src
        packet[Ether].dst = new_dst
