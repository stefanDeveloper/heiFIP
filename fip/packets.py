from abc import ABC, abstractmethod

from scapy.all import DNS, IP, UDP, IPv6, Ether, Packet, wrpcap, rdpcap, RandIP, RandMAC, TCP
from typing import Type
from scapy.layers.http import HTTPRequest, HTTPResponse

import os

from fip.ssh import SSH
from fip.custom_header import custom_IP, custom_IPv6, custom_HTTP_Request, custom_HTTP_Response, custom_DNS, custom_TCP, custom_UDP


class PCAPProcessed(ABC):
    def __init__(self, file: str, packets: list[Packet]) -> None:
        self.file = file
        self.packets = packets
    def __getitem__(self, i):
        return self.__dict__[i]


class PacketProcessor(ABC):
    def __init__(self, dir: str, file_extension="pcap") -> None:
        assert os.path.exists(dir)

        self.dir = dir
        self.files = []
        if os.path.isdir(dir):
            self.__get_filenames(file_extension)
        elif os.path.isfile(dir):
            self.files = [dir]

    def __get_filenames(self, file_extension) -> None:
        for filename in os.listdir(self.dir):
            if filename.endswith(f'.{file_extension}'):
                file = os.path.join(self.dir, filename)
                self.files.append(file)

    def __enter__(self):
        return self

    def __iter__(self):
        return self

    def next(self) -> PCAPProcessed:
        """
        implement the iterator protocol on a set of packets in a pcap file
        """
        try:
            file = self.files.pop(0)
            return PCAPProcessed(os.path.basename(file), self.read_packets(file))
        except IndexError:
            raise StopIteration

    __next__ = next

    def write_packet(self) -> None:
        wrpcap(f'{self.filename}_converted.pcap', self.packets, append=True)

    def read_packets(self, file) -> str:
        pcap = rdpcap(filename=file)
        packets = []
        for pkt in pcap:
            processed_packet = self.preprocessing(pkt)
            if processed_packet != None:
                packets.append(processed_packet)
        return packets

    def preprocessing(self, packet: Packet) -> Packet:
        for layer_class in packet.getlayer():
            packet = self.preprocess_layer(packet, layer_class)
    
    def preprocess_layer(self, packet: Packet, layer_class: Type[Packet]) -> Packet:
        if layer_class == IP:
            new_layer = custom_IP(version=packet[IP].version,
                                        tos=packet[IP].tos, ttl=packet[IP].ttl,
                                        flags=packet[IP].flags,
                                        proto=packet[IP].proto)
        elif layer_class == IPv6:
            new_layer = custom_IPv6(
                version = packet[IPv6].version,
                tc = packet[IPv6].tc, 
                nh = packet[IPv6].nh,
                hlim = packet[IPv6].hlim,
            )
        
        elif layer_class == TCP:
            new_layer = custom_TCP(flags=packet[TCP].flags, 
            options=packet[TCP].options)

        elif layer_class == UDP:
            new_layer = custom_UDP()

        elif layer_class == HTTPRequest:
            new_layer = custom_HTTP_Request(
                Method = packet[HTTPRequest].Method,
                Path = packet[HTTPRequest].Path,
                User_Agent = packet[HTTPRequest].User_Agent,
                Content_Type = packet[HTTPRequest].Content_Type,
                Connection = packet[HTTPRequest].Connection,
                Accept = packet[HTTPRequest].Accept,
                Accept_Charset = packet[HTTPRequest].Accept_Charset,
                Cookie = packet[HTTPRequest].Cookie,
                TE = packet[HTTPRequest].TE
                )

        elif layer_class == HTTPResponse:
            new_layer = custom_HTTP_Response(
                Status_Code = packet[HTTPResponse].Status_Code,
                Server = packet[HTTPResponse].Server,
                Content_Type = packet[HTTPResponse].Content_Type,
                Connection = packet[HTTPResponse].Connection,
                Content_Encoding = packet[HTTPResponse].Content_Encoding,
                Set_Cookie = packet[HTTPResponse].Set_Cookie,
                )
        elif layer_class == DNS:
            new_layer = custom_DNS(
                qr = packet[DNS].qr,
                opcode = packet[DNS].opcode,
                aa = packet[DNS].aa,
                tc = packet[DNS].tc,
                rd = packet[DNS].rd,
                ra = packet[DNS].ra,
                z = packet[DNS].z,
                ad = packet[DNS].ad,
                cd = packet[DNS].cd,
                rcode = packet[DNS].rcode,
                qd = packet[DNS].qd,
                an = packet[DNS].an,
                ns = packet[DNS].ns,
                ar = packet[DNS].ar
            )
        
        else:
            return packet

        layers = packet.layers()
        for i, layer in enumerate(layers):
            if layer == layer_class:
                if i != (len(layers) - 1):
                    after_layer = packet[layers[i+1]]
                    new_layer /= after_layer
                if i != 0:
                    packet[layers[i-1]].remove_payload()
                    packet /= new_layer
                else:
                    packet = new_layer
                break

        return packet



    def __exit__(self, exc_type, exc_value, tracback) -> None:
        pass


class HTTPPacketProcessor(PacketProcessor):
    def __init__(self, dir) -> None:
        PacketProcessor.__init__(self, dir)

    def preprocessing(self, packet: Packet)-> Packet:
        processed_packet = packet
        if processed_packet.haslayer(Ether):
            processed_packet[Ether].src = RandIP()._fix()
            processed_packet[Ether].dst = RandIP()._fix()

        if processed_packet.haslayer(IP):
            processed_packet[IP].src = RandIP()._fix()
            processed_packet[IP].dst =RandIP()._fix()
        elif processed_packet.haslayer(IPv6):
            processed_packet[IPv6].src = RandIP()._fix()
            processed_packet[IPv6].dst = RandIP()._fix()


        return processed_packet

    def __enter__(self):
        return self


class SSHPacketProcessor(PacketProcessor):
    def __init__(self, dir) -> None:
        PacketProcessor.__init__(self, dir)

    def preprocessing(self, packet: Packet)-> Packet:
        processed_packet = packet
        #if processed_packet.haslayer(Ether):
        #    processed_packet[Ether].src = "00:00:00:00:00:00"
        #    processed_packet[Ether].dst = "00:00:00:00:00:00"

        #if processed_packet.haslayer(IP):
        #    processed_packet[IP].src = "0.0.0.0"
        #    processed_packet[IP].dst = "0.0.0.0"

        #if processed_packet.haslayer(SSH):
        #    processed_packet = processed_packet[SSH]

        return processed_packet

    def __enter__(self):
        return self
