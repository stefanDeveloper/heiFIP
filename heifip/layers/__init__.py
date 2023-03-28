import os
from abc import ABC
from enum import Enum, unique
from typing import Type

from scapy.all import (Packet, RandIP, RandIP6, RandMAC, Raw, rdpcap, sniff,
                       wrpcap)
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse, _HTTPContent
from scapy.layers.inet import IP, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6

from heifip.exceptions import FIPWrongParameterException
from heifip.layers.dns import DNSPacket
from heifip.layers.http import HTTPRequestPacket, HTTPResponsePacket
from heifip.layers.ip import IPPacket
from heifip.layers.packet import FIPPacket, UnknownPacket
from heifip.layers.transport import TransportPacket

__author__ = "Stefan Machmeier"
__copyright__ = "Copyright 2023, heiFIP"
__credits__ = ["Manuel Trageser"]
__license__ = "EUPL"
__version__ = "0.0.1"
__maintainer__ = "Stefan Machmeier"
__email__ = "stefan.machmeier@uni-heidelberg.de"
__status__ = "Production"

SUPPORTED_HEADERS = [IP, IPv6, DNS, HTTPRequest, HTTPResponse, TCP, UDP]


@unique
class PacketProcessorType(Enum):
    NONE = 1
    HEADER = 2
    PAYLOAD = 3


class PacketProcessor:
    def __init__(
        self,
        file_extension="pcap",
    ) -> None:
        pass

    def write_packet(self) -> None:
        # Write pcap
        wrpcap(f"{self.filename}_converted.pcap", self.packets, append=True)

    def read_packets(self, file, preprocessing_type: PacketProcessorType) -> list:
        assert os.path.isfile(file)

        # Read PCAP file with Scapy
        # pcap = rdpcap(filename=file)
        packets = []
        pcap = sniff(offline=file)
        for pkt in pcap:
            # Start preprocessing for each packet
            processed_packet = self.__preprocessing(pkt, preprocessing_type)
            # In case packet returns None
            if processed_packet != None:
                packets.append(processed_packet)
        return packets

    def __preprocessing(self, packet: Packet, preprocessing_type: PacketProcessorType) -> FIPPacket:
        # match preprocessing_type:
        #     case PacketProcessorType.HEADER:
        #         self.__preprossing_header(Packet)
        #     case PacketProcessorType.PAYLOAD:
        #         self.__preprocessing_payload(Packet)
        #     case _:
        #         pass

        fippacket = None
        if packet.haslayer(_HTTPContent):
            if packet.haslayer(HTTPRequest):
                fippacket = HTTPRequestPacket(packet)
            elif packet.haslayer(HTTPResponse()):
                fippacket = HTTPResponsePacket(packet)
        elif packet.haslayer(DNS):
            fippacket = DNSPacket(packet)
        elif packet.haslayer(TCP) or packet.haslayer(UDP):
            fippacket = TransportPacket(packet)
        elif packet.haslayer(IP) or packet.haslayer(IPv6):
            fippacket = IPPacket(packet)
        elif packet.haslayer(Ether):
            pafippacket = FIPPacket(packet)
        else:
            fippacket =  UnknownPacket(packet)
        return fippacket

    def __preprossing_header(self, packet):
        headers = SUPPORTED_HEADERS + [Raw]
        layers = packet.packet.layers()
        if len([layer for layer in layers if layer in headers]) == 0:
            return None
        for layer_class in layers:
            if layer_class in headers:
                new_layer = self.preprocess_layer(packet, layer_class)
                if not new_packet:
                    new_packet = new_layer
                else:
                    new_packet /= new_layer
                pass

    def __preprocessing_payload(self, packet: Packet):
        if packet.haslayer(Raw):
            return packet[Raw]
        else:
            return None

    # def preprocess_layer(self, packet: Packet, layer_class: Type[Packet]) -> Packet:
    #     layer_copy = packet[layer_class]

    #     new_layer
    #     match layer_class:
    #         case HTTPRequest:
    #             pass
    #         case HTTPResponse:
    #             pass
    #         case DNS:
    #             pass
    #         case TCP:
    #             pass
    #         case UDP:
    #             pass
    #         case IPv6:
    #             pass
    #         case IP:
    #             pass
    #         case Raw:
    #             new_layer = layer_copy

    #     return new_layer
