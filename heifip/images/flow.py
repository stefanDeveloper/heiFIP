import binascii
import logging

import numpy as np
from scapy.all import Packet, raw

from heifip.images import NetworkTrafficImage


class FlowImage(NetworkTrafficImage):
    def __init__(
        self,
        packets,
        dim=16,
        fill=0,
        append=False,
    ) -> None:
        NetworkTrafficImage.__init__(self, fill, dim)
        self.packets = packets
        self.append = append
        self.matrix, self.binaries = self.__get_matrix(self.dim, self.append, self.fill, self.packets)
        del packets
        

    def __get_matrix(self, dim: int, append: bool, fill: int, packets: [Packet]):
        """
            Creates a matrix of a list of Scapy Packet.
        """
        binaries = []
        for packet in self.packets:
            # get Hex data
            hexst = binascii.hexlify(raw(packet.packet))
            # Append octet as integer
            binaries.append(
                [int(hexst[i : i + 2], 16) for i in range(0, len(hexst), 2)]
            )
        fh = None
        # Append packets after another or write each packet in a row
        if append:
            fh = np.concatenate([np.array(xi) for xi in binaries])
            rn = len(fh) // dim + (len(fh) % dim > 0)
            fh = np.pad(fh, (0, (rn * dim) - fh.shape[0]), 'constant')
            fh = fh.reshape(rn, dim)
        else:
            length = max(map(len, binaries))
            fh = np.array([xi + [fill] * (length - len(xi)) for xi in binaries])

        fh = np.uint8(fh)

        return fh, binaries
