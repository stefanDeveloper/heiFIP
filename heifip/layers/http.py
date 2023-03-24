from tcp import TCPPacketProcessor

class HTTPPacketProcessor(TCPPacketProcessor):
    def __init__(self, dir) -> None:
        PacketProcessor.__init__(self, dir)

    def __enter__(self):
        return self
