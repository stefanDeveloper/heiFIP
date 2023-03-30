from scapy.all import Packet

from heifip.layers.transport import TransportPacket


class SSHPacketProcessor(TransportPacket):
    def __init__(self, packet: Packet, address_mapping={}, layer_map={}):
        TransportPacket.__init__(self, packet, address_mapping, layer_map)

    def header_preprocessing(self):
        super().header_preprocessing()