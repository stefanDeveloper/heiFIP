from typing import Type

from scapy.all import Packet
from scapy.layers.http import HTTPRequest, HTTPResponse

from heifip.layers.transport import TransportPacket
from heifip.plugins.header import (CustomHTTP, CustomHTTP_Request,
                                   CustomHTTP_Response)


class HTTPPacket(TransportPacket):
    def __init__(self, packet: Packet):
        TCPPacket.__init__(self, packet)
    def header_preprocessing(self):
        super().header_preprocessing()


class HTTPRequestPacket(HTTPPacket):
    def __init__(self, packet: Packet):
        HTTPPacket.__init__(self, packet)

    def header_preprocessing(self):
        layer_copy = packet[HTTPRequest]
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
        layer_copy.payload = self.packet[HTTPRequest].payload
        self.packet[HTTPRequest] = layer_copy

        super().header_preprocessing()


class HTTPResponsePacket(HTTPPacket):
    def __init__(self, packet: Packet):
        HTTPPacket.__init__(self, packet)

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

        layer_copy.payload = self.packet[HTTPResponse].payload

        self.packet[HTTPResponse] = layer_copy

        super().header_preprocessing()
