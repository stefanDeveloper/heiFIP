from abc import ABC

from scapy.all import (
    Packet,
    wrpcap,
    rdpcap,
    RandIP,
    RandIP6,
    RandMAC,
    Raw,
)
from typing import Type
from scapy.layers.http import HTTPRequest, HTTPResponse, _HTTPContent
from scapy.layers.inet import IP, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS

import os
from enum import Enum, unique
from heifip.exceptions import FIPWrongParameterException
from .http import HTTPRequestPacket, HTTPResponsePacket
from .ip import IPPacket
from .dns import DNSPacket
from .transport import TransportPacket
from .packet import FIPPacket, UnknownPacket

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
        # TODO Add BPF
        pcap = rdpcap(filename=file)
        packets = []
        # Go through all packets
        for pkt in pcap:
            # Start preprocessing for each packet
            processed_packet = self.__preprocessing(pkt, preprocessing_type)
            # In case packet returns None
            if processed_packet != None:
                packets.append(processed_packet)
        return packets

    def __preprocessing(self, packet: Packet, preprocessing_type: PacketProcessorType) -> FIPPacket:
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

        match preprocessing_type:
            case PacketProcessorType.HEADER:
                self.__preprossing_header(fippacket.packet)
            case PacketProcessorType.PAYLOAD:
                self.__preprocessing_payload(fippacket.packet)
            case _:
                pass
        return fippacket

    def __preprossing_header(self, packet: Packet()):
        headers = SUPPORTED_HEADERS + [Raw]
        layers = packet.layers()
        if len([layer for layer in layers if layer in headers]) == 0:
            return None
        new_packet = None
        for layer_class in layers:
            if layer_class in headers:
                # new_layer = self.preprocess_layer(packet, layer_class)
                # if not new_packet:
                #     new_packet = new_layer
                # else:
                #     new_packet /= new_layer
                pass

        return new_packet

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
