import binascii

import numpy as np
from scapy.all import Packet, raw

from heifip.images import NetworkTrafficImage


class PacketImage(NetworkTrafficImage):
    def __init__(
        self,
        packet: Packet,
        dim=8,
        fill=0,
        auto_dim=False
    ) -> None:
        NetworkTrafficImage.__init__(self, fill, dim)
        self.auto_dim = auto_dim
        self.matrix, self.binaries = self.__get_matrix(self.dim, self.auto_dim, self.fill, packet)

        del packet

    def __get_matrix(self, dim: int, auto_dim: int, fill: int, packet: Packet):
        # get Hex data
        hexst = binascii.hexlify(raw(packet.packet))
        # Append octet as integer
        binaries = [int(hexst[i: i + 2], 16) for i in range(0, len(hexst), 2)]
        # Get min dim
        length = len(binaries)
        if auto_dim:
            dim = int(np.ceil(np.sqrt(length)))

        # Create array and shape it to dim
        fh = np.array(binaries + [fill] * (dim * dim - len(binaries)))
        fh = fh[0:dim * dim].reshape(dim, dim)

        fh = np.uint8(fh)

        return fh, binaries
