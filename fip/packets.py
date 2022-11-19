from abc import ABC, abstractmethod

from scapy.all import DNS, IP, UDP, IPv6, Ether, Packet, wrpcap, rdpcap, RandIP, RandMAC, TCP, Raw
from typing import Type
from scapy.layers.http import HTTPRequest, HTTPResponse

import os

from fip.ssh import SSH
from fip.custom_header import SUPPORTED_HEADERS, custom_IP, custom_IPv6, custom_HTTP_Request, custom_HTTP_Response, custom_DNS, custom_DNSQR, custom_DNSRR, custom_TCP, custom_UDP

class PCAPProcessed(ABC):
    def __init__(self, file: str, packets: list[Packet]) -> None:
        self.file = file
        self.packets = packets
    def __getitem__(self, i):
        return self.__dict__[i]


class PacketProcessor(ABC):
    def __init__(self, dir: str, preprocessing_type: str, file_extension="pcap") -> None:
        assert os.path.exists(dir)

        self.dir = dir
        self.preprocessing_type = preprocessing_type
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
        if self.preprocessing_type == "header":
            headers = SUPPORTED_HEADERS + [Raw]
            layers = packet.layers()
            if len([layer for layer in layers if layer in headers]) == 0:
                return None
            
            previous_layer_class = None
            for i,layer_class in enumerate(layers):
                next_layer_class = None
                if i < len(layers)-1:
                    next_layer_class = layers[i+1]
                if layer_class in headers:
                    packet, new_layer_class = self.preprocess_layer(packet, layer_class, previous_layer_class, next_layer_class)
                    previous_layer_class = new_layer_class
                else:
                    packet = self.remove_layer(packet, layer_class, previous_layer_class, next_layer_class)

        elif self.preprocessing_type == "payload":
            if packet.haslayer(Raw):
                return packet[Raw]
            else:
                return None

        return packet

    def remove_layer(self, packet: Packet, layer_class: Type[Packet], previous_layer_class: Type[Packet], next_layer_class: Type[Packet]) -> Packet:
        #check if completly empty after this
        if not previous_layer_class and not next_layer_class:
            return None
            
        if next_layer_class:
            after_layer = packet[next_layer_class]
        if previous_layer_class:
            packet[previous_layer_class].remove_payload()
            if next_layer_class:
                packet /= after_layer
        else:
            packet = after_layer
        
        return packet
            
    
    def preprocess_DNS_messages(self, packet: Packet, message_type: str) -> None:
        message = getattr(packet[DNS], message_type)
        
        if message_type == "qd":
            new_message = custom_DNSQR(
                qname = message.qname,
                qtype = message.qtype
                )
            
            while message:=message.payload:
                new_message /= custom_DNSQR(
                    qname = message.qname,
                    qtype = message.qtype,
                    )
        else:
            new_message = custom_DNSRR(
                rrname = message.rrname,
                type = message.type,
                ttl = message.ttl
                )
            
            while message:=message.payload:
                new_message /= custom_DNSRR(
                    rrname = message.rrname,
                    type = message.type,
                    ttl = message.ttl
                    )
        
        setattr(packet[DNS], message_type, new_message)

    
    def preprocess_layer(self, packet: Packet, layer_class: Type[Packet], previous_layer_class: Type[Packet], next_layer_class: Type[Packet]) -> Packet:
        layer_copy = packet[layer_class]
        if layer_class == IP:
            new_layer = custom_IP(
                version=layer_copy.version,
                tos=layer_copy.tos, 
                ttl=layer_copy.ttl,
                flags=layer_copy.flags,
                proto=layer_copy.proto)
            new_layer_class = custom_IP

        elif layer_class == IPv6:
            new_layer = custom_IPv6(
                version = layer_copy.version,
                tc = layer_copy.tc, 
                nh = layer_copy.nh,
                hlim = layer_copy.hlim,
            )
            new_layer_class = custom_IPv6
        
        elif layer_class == TCP:
            new_layer = custom_TCP(
                flags=layer_copy.flags, 
                options=layer_copy.options
                )
            new_layer_class = custom_TCP

        elif layer_class == UDP:
            new_layer = custom_UDP()
            new_layer_class = custom_UDP

        elif layer_class == HTTPRequest:
            new_layer = custom_HTTP_Request(
                Method = layer_copy.Method,
                Path = layer_copy.Path,
                User_Agent = layer_copy.User_Agent,
                Content_Type = layer_copy.Content_Type,
                Connection = layer_copy.Connection,
                Accept = layer_copy.Accept,
                Accept_Charset = layer_copy.Accept_Charset,
                Cookie = layer_copy.Cookie,
                TE = layer_copy.TE
                )
            new_layer_class = custom_HTTP_Request

        elif layer_class == HTTPResponse:
            new_layer = custom_HTTP_Response(
                Status_Code = layer_copy.Status_Code,
                Server = layer_copy.Server,
                Content_Type = layer_copy.Content_Type,
                Connection = layer_copy.Connection,
                Content_Encoding = layer_copy.Content_Encoding,
                Set_Cookie = layer_copy.Set_Cookie,
                )
            new_layer_class = custom_HTTP_Response
                
        elif layer_class == DNS:
            if packet[DNS].qd:
                self.preprocess_DNS_messages(packet, "qd")
            if packet[DNS].an:
                self.preprocess_DNS_messages(packet, "an")
            if packet[DNS].ns:
                self.preprocess_DNS_messages(packet, "ns")
            if packet[DNS].ar:
                self.preprocess_DNS_messages(packet, "ar")
            
            layer_copy = packet[DNS]

            new_layer = custom_DNS(
                qr = layer_copy.qr,
                opcode = layer_copy.opcode,
                aa = layer_copy.aa,
                tc = layer_copy.tc,
                rd = layer_copy.rd,
                ra = layer_copy.ra,
                z = layer_copy.z,
                ad = layer_copy.ad,
                cd = layer_copy.cd,
                rcode = layer_copy.rcode,
                qd = layer_copy.qd,
                an = layer_copy.an,
                ns = layer_copy.ns,
                ar = layer_copy.ar
            )
            new_layer_class = custom_DNS
        
        else:
            return packet, layer_class

        if next_layer_class:
            after_layer = packet[next_layer_class]
            new_layer /= after_layer
        if previous_layer_class:
            packet[previous_layer_class].remove_payload()
            packet /= new_layer
        else:
            packet = new_layer
        
        return packet, new_layer_class

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
