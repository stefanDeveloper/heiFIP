from tcp import TCPPacketProcessor

class SSHPacketProcessor(TCPPacketProcessor):
    def __init__(self, dir) -> None:
        PacketProcessor.__init__(self, dir)

    def preprocessing(self, packet: Packet)-> Packet:
        processed_packet = packet

        return processed_packet

    def __enter__(self):
        return self