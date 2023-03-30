from typing import Type

from scapy.all import Packet
from scapy.layers.dns import DNS

from heifip.layers.transport import TransportPacket
from heifip.plugins.header import CustomDNS, CustomDNSQR, CustomDNSRR


class DNSPacket(TransportPacket):
    def __init__(self, packet: Packet, address_mapping={}, layer_map={}) -> None:
        TransportPacket.__init__(self, packet, address_mapping, layer_map)
    
    def header_preprocessing(self):
        # if self.packet[DNS].qd:
        #     self.__header_preprocessing_message_type(self.packet, "qd")
        # if self.packet[DNS].an:
        #     self.__header_preprocessing_message_type(self.packet, "an")
        # if self.packet[DNS].ns:
        #     self.__header_preprocessing_message_type(self.packet, "ns")
        # if self.packet[DNS].ar:
        #     self.__header_preprocessing_message_type(self.packet, "ar")

        layer_copy = self.packet[DNS]

        new_layer = CustomDNS(
            qr=layer_copy.qr,
            opcode=layer_copy.opcode,
            aa=layer_copy.aa,
            tc=layer_copy.tc,
            rd=layer_copy.rd,
            ra=layer_copy.ra,
            z=layer_copy.z,
            ad=layer_copy.ad,
            cd=layer_copy.cd,
            rcode=layer_copy.rcode,
            qd=layer_copy.qd,
            an=layer_copy.an,
            ns=layer_copy.ns,
            ar=layer_copy.ar,
        )

        self.packet[DNS] /= new_layer

        super().header_preprocessing()

    
    def __header_preprocessing_message_type(self, packet: Packet, message_type: str):
        message = getattr(packet[DNS], message_type)
        if message_type == "qd":
            new_message = CustomDNSQR(qname=message.qname, qtype=message.qtype)
            
            message = message.payload
            while message:
                new_message /= CustomDNSQR(
                    qname=message.qname,
                    qtype=message.qtype,
                )
        else:
            if message_type != "ar":
                new_message = CustomDNSRR(
                    rrname=message.rrname, type=message.type, ttl=message.ttl
                )

                message = message.payload
                while message:
                    new_message /= CustomDNSRR(
                        rrname=message.rrname, type=message.type, ttl=message.ttl
                    )
        
        if message_type != "ar":
            setattr(packet[DNS], message_type, new_message)
