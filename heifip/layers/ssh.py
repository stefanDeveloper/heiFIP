from scapy.all import Packet

from heifip.layers.transport import TransportPacket


class SSHPacketProcessor(TransportPacket):
    def __init__(self, packet: Packet):
        TransportPacket.__init__(self, packet)
