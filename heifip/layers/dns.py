from ip import IPPacketProcessor

class DNSPacketProcessor(IPPacketProcessor):
    def __init__(self, dir) -> None:
        PacketProcessor.__init__(self, dir)

    def __enter__(self):
        return self
