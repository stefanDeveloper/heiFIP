import hashlib

from scapy.all import RandMAC
from scapy.layers.inet import Ether


class FIPPacket:
    def __init__(self, packet, address_mapping={}, layer_map={}):
        self.address_mapping = address_mapping
        self.packet = packet
        self.hash = hashlib.md5().hexdigest()

        if layer_map == {}:
            self.layer_map = self.__get_layers()

    def __get_layers(self):
        layer_map = dict()
        layers = self.packet.layers()
        for layer_class in layers:
            layer_map[layer_class] = 1
        return layer_map

    def convert(self, packet_type, packet):
        return packet_type(packet.packet, packet.address_mapping, packet.layer_map)

    def header_preprocessing(self):
        pass

class UnknownPacket(FIPPacket):
    def __init__(self, packet, address_mapping={}, layer_map={}):
        FIPPacket.__init__(self, packet, address_mapping, layer_map)

    def header_preprocessing(self):
        super().header_preprocessing()

class EtherPacket(FIPPacket):
    def __init__(self, packet, address_mapping={}, layer_map={}):
        FIPPacket.__init__(self, packet, layer_map, address_mapping)
        
        if Ether in self.layer_map:
            self.__filter()

    def __filter(self):
        previous_src = self.packet[Ether].src
        previous_dst = self.packet[Ether].dst

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

        self.packet[Ether].src = new_src
        self.packet[Ether].dst = new_dst

    def header_preprocessing(self):
        super().header_preprocessing()