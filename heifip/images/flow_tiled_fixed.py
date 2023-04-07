import binascii
import logging

import numpy as np
from scapy.all import Packet, raw

from heifip.images import NetworkTrafficImage

class FlowImageTiledFixed(NetworkTrafficImage):
    def __init__(
        self,
        packets,
        dim=16,
        fill=0,
        cols=3,
    ) -> None:
        NetworkTrafficImage.__init__(self, fill, dim)
        self.packets = packets
        self.cols = cols
        self.matrix, self.binaries = self.__get_matrix_tiled(self.fill, self.dim, self.cols, packets)
        del packets

    def __get_matrix_tiled(self, fill: int, dim: int, cols: int, packets: [Packet]):
        """
            Creates a matrix of a list of Scapy Packet.
            Packets are tiled into a quadratic representation.
        """
        binaries = []
        for packet in self.packets:
            # get Hex data
            hexst = binascii.hexlify(raw(packet.packet))
            # Append octet as integer
            binaries.append(
                [int(hexst[i : i + 2], 16) for i in range(0, len(hexst), 2)]
            )

        result = []
        for x in binaries:
            x = x[: dim * dim]
            x = np.array(x + [fill] * (dim * dim - len(x)))
            x = x.reshape(dim, dim)
            result.append(x)

        # Create tiled image
        fh = self.__tile_images(result, cols, dim)
        # Convert to int
        fh = np.uint8(fh)
        return fh, binaries

    def __tile_images(self, images, cols: int, dim: int):
        """Tile images of same size to grid with given number of columns.

        Args:
            images (collection of ndarrays)
            cols (int): number of colums

        Returns:
            ndarray: stitched image
        """
        k = 0
        rows = []
        for i in range(0, cols):
            row = None
            for j in range(0, cols):
                if len(images) > k:
                    im = images[k]
                else:
                    im = np.zeros((dim, dim))
                
                if row is None:
                    row = im
                else:
                    row = np.concatenate((row, im), axis=1)
                k += 1
                
            rows.append(row)
        tiled = np.concatenate(rows)

        return tiled