from .transport import TransportPacket

from heifip.plugins.header import CustomDNS, CustomDNSQR, CustomDNSRR
from scapy.all import Packet
from scapy.layers.dns import DNS

from typing import Type


class DNSPacket(TransportPacket):
    def __init__(self, packet: Packet) -> None:
        TransportPacket.__init__(self, packet)

    def header_preprocessing(self, packet: Packet, layer_class: Type[Packet]):
        layer_copy = packet[layer_class]
        if packet[DNS].qd:
            self.__filter_dns_type(packet, "qd")
        if packet[DNS].an:
            self.__filter_dns_type(packet, "an")
        if packet[DNS].ns:
            self.__filter_dns_type(packet, "ns")
        if packet[DNS].ar:
            self.__filter_dns_type(packet, "ar")

        layer_copy = packet[DNS]

        return CustomDNS(
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

    def __header_preprocessing_message_type(self, packet: Packet, message_type: str):
        message = getattr(packet[DNS], message_type)
        if message_type == "qd":
            new_message = CustomDNSQR(qname=message.qname, qtype=message.qtype)

            while message := message.payload:
                new_message /= CustomDNSQR(
                    qname=message.qname,
                    qtype=message.qtype,
                )
        else:
            if message_type != "ar":
                new_message = CustomDNSRR(
                    rrname=message.rrname, type=message.type, ttl=message.ttl
                )

                while message := message.payload:
                    new_message /= CustomDNSRR(
                        rrname=message.rrname, type=message.type, ttl=message.ttl
                    )

        setattr(packet[DNS], message_type, new_message)
