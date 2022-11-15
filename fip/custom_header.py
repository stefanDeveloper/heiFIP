from scapy.all import DNSQRField, DNSRRField, ShortEnumField, IntField, Packet, BitField, BitEnumField, FlagsField, XByteField, ByteField, ByteEnumField, StrField, IP_PROTOS, TCPOptionsField
from scapy.layers.inet6 import  ipv6nh
from scapy.all import IP, IPv6, DNS, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNSStrField, dnstypes, InheritOriginDNSStrPacket
SUPPORTED_HEADERS = [IP, IPv6, DNS, HTTPRequest, HTTPResponse, TCP, UDP]

class custom_IP(Packet):
    name = "IP"
    fields_desc = [
        BitField("version", 4, 4),
        FlagsField("flags", 0, 4, ["R", "DF", "MF"]), # normally 3 bits last bit will always be 0
        XByteField("tos", 0),
        ByteField("ttl", 64),
        ByteEnumField("proto", 0, IP_PROTOS),
        ]

class custom_IPv6(Packet):
    name = "IPv6"
    field_desc = [
        BitField("version", 6, 8), # normally 4 bits, last 4bits will always be 0
        BitField("tc", 0, 8),
        ByteEnumField("nh", 59, ipv6nh),
        ByteField("hlim", 64)
    ]

class custom_TCP(Packet):
    name = "TCP"
    fields_desc = [
        FlagsField("flags", 0x2, 16, "FSRPAUECN"),
        TCPOptionsField("options", "")
    ]

class custom_UDP(Packet):
    name = "UDP"
    fields_desc = []

class custom_HTTP(Packet):
    def self_build(self):
        p = b""

        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            #when Value is not set
            if not val:
                continue
            if f.name not in ['Method', 'Path', 'Status_Code']:
                val = bytes((f.name).encode()) + b": " + bytes(val)
            if f.name in ['Method', 'Path', 'Status_Code']:
                seperator = b' '
            else:
                seperator = b'\r\n'

            p = f.addfield(self, p, val + seperator)
        
        return p


class custom_HTTP_Request(custom_HTTP):
    name = "HTTP Request"
    fields_desc = [
        StrField("Method", "GET"),
        StrField("Path", "/"),
        StrField("User_Agent", None),
        StrField("Content_Type", None),
        StrField("Connection", None),
        StrField("Accept", None),
        StrField("Accept_Charset", None),
        StrField("Accept_Encoding", None),
        StrField("Cookie", None),
        StrField("TE", None)
    ]

class custom_HTTP_Response(custom_HTTP):
    name = "HTTP Response"
    fields_desc = [
        StrField("Status_Code", "200"),
        StrField("Connection", None),
        StrField("Content_Encoding", None),
        StrField("Content_Type", None),
        StrField("Server", None),
        StrField("Set_Cookie", None)
    ]

class custom_DNSQR(InheritOriginDNSStrPacket):
    name = "DNS Question Record"
    show_indent = 0 
    fields_desc = [
        DNSStrField("qname", "none"),
        ShortEnumField("qtype", 1, dnstypes)
    ]

class custom_DNSRR(InheritOriginDNSStrPacket):
    name = "DNS Resource Record"
    show_indent = 0
    fields_desc = [
        DNSStrField("rrname", ""),
        ShortEnumField("type", 1, dnstypes),
        IntField("ttl", 0)
    ]

class custom_DNS(Packet):
    name = "DNS"
    fields_desc = [
        BitField("qr", 0, 1),
        BitEnumField("opcode", 0, 4, {0: "QUERY", 1: "IQUERY", 2: "STATUS"}),
        BitField("aa", 0, 1),
        BitField("tc", 0, 1),
        BitField("rd", 1, 1),
        BitField("ra", 0, 1),
        BitField("z", 0, 1),
        BitField("ad", 0, 1),
        BitField("cd", 0, 1),
        BitEnumField("rcode", 0, 4, {0: "ok", 1: "format-error",
                                     2: "server-failure", 3: "name-error",
                                     4: "not-implemented", 5: "refused"}),
        DNSQRField("qd", "", None),
        DNSRRField("an", "", None),
        DNSRRField("ns", "", None),
        DNSRRField("ar", "", None),
    ]
