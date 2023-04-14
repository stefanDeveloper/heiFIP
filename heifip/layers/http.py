import hashlib
from typing import Type

from scapy.all import Packet
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from heifip.layers.transport import TransportPacket
from heifip.plugins.header import (CustomHTTP, CustomHTTP_Request,
                                   CustomHTTP_Response)


class HTTPPacket(TransportPacket):
    def __init__(self, packet: Packet, address_mapping={}, layer_map={}):
        TransportPacket.__init__(self, packet, address_mapping, layer_map)
    def header_preprocessing(self):
        super().header_preprocessing()


class HTTPRequestPacket(HTTPPacket):
    def __init__(self, packet: Packet, address_mapping={}, layer_map={}):
        HTTPPacket.__init__(self, packet, address_mapping, layer_map)
        # self.hash = hashlib.md5(f"{self.packet[HTTPRequest].Path},{self.packet[HTTPRequest].Method},{self.packet[HTTPRequest].Accept}".encode('utf-8')).hexdigest()
        self.hash = hashlib.md5(f"{self.packet[HTTPRequest].Method},{self.packet[HTTPRequest].Accept}".encode('utf-8')).hexdigest()
        if Raw in self.layer_map:
            self.packet[HTTPRequest].remove_payload()

    def header_preprocessing(self):
        layer_copy = self.packet[HTTPRequest]
        layer_copy = CustomHTTP_Request(
            Method=layer_copy.Method,
            Path=layer_copy.Path,
            User_Agent=layer_copy.User_Agent,
            Content_Type=layer_copy.Content_Type,
            Connection=layer_copy.Connection,
            Accept=layer_copy.Accept,
            Accept_Charset=layer_copy.Accept_Charset,
            Cookie=layer_copy.Cookie,
            TE=layer_copy.TE,
        )

        if not self.packet[HTTPRequest].payload is None:
            layer_copy.payload = self.packet[HTTPRequest].payload

        self.packet[HTTPRequest] = layer_copy

        super().header_preprocessing()


class HTTPResponsePacket(HTTPPacket):
    def __init__(self, packet: Packet, address_mapping={}, layer_map={}):
        HTTPPacket.__init__(self, packet, address_mapping, layer_map)
        # self.hash = hashlib.md5(f"{self.packet[HTTPResponse].Server},{self.packet[HTTPResponse].Status_Code},{self.packet[HTTPResponse].Connection}".encode('utf-8')).hexdigest()
        self.hash = hashlib.md5(f"{self.packet[HTTPResponse].Status_Code},{self.packet[HTTPResponse].Connection}".encode('utf-8')).hexdigest()
        if Raw in self.layer_map:
            self.packet[HTTPResponse].remove_payload()

    def header_preprocessing(self):
        layer_copy = self.packet[HTTPResponse]
        layer_copy = CustomHTTP_Response(
            Status_Code=layer_copy.Status_Code,
            Server=layer_copy.Server,
            Content_Type=layer_copy.Content_Type,
            Connection=layer_copy.Connection,
            Content_Encoding=layer_copy.Content_Encoding,
            Set_Cookie=layer_copy.Set_Cookie,
            Transfer_Encoding=layer_copy.Transfer_Encoding,
        )

        if self.packet[HTTPResponse].payload != None:
            layer_copy.payload = self.packet[HTTPResponse].payload

        self.packet[HTTPResponse] = layer_copy

        super().header_preprocessing()
