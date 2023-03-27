from .transport import TransportPacket
from scapy.all import Packet

class SSHPacketProcessor(TransportPacket):
    def __init__(self, packet: Packet):
        TransportPacket.__init__(self, packet)
