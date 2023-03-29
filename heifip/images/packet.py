import binascii
import logging

import numpy as np
from scapy.all import Packet, raw

from heifip.images import NetworkTrafficImage


class PacketImage(NetworkTrafficImage):
    def __init__(
        self,
        packet: Packet,
        dim=8,
        fill=0,
    ) -> None:
        NetworkTrafficImage.__init__(self, fill, dim)
        self.matrix, self.binaries = self.__get_matrix(self.dim, packet)

        del packet

    def __get_matrix(self, dim, packet):
        """

        """
        # get Hex data
        hexst = binascii.hexlify(raw(packet.packet))
        # Append octet as integer
        binaries = [int(hexst[i: i + 2], 16) for i in range(0, len(hexst), 2)]

        # Get min dim
        length = len(binaries)
        auto_dim = int(np.ceil(np.sqrt(length)))
        if auto_dim > dim:
            dim = dim

        # Create array and shape it to dim
        fh = np.array(binaries + [self.fill] * (self.dim * self.dim - len(binaries)))
        fh = fh[0:self.dim * self.dim].reshape(self.dim, self.dim)

        fh = np.uint8(fh)

        return fh, binaries
