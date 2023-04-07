import binascii
import logging

import numpy as np
from scapy.all import Packet, raw

from heifip.images import NetworkTrafficImage

class FlowImageTiledAuto(NetworkTrafficImage):
    def __init__(
        self,
        packets,
        dim=16,
        fill=0,
        auto_dim=False,
    ) -> None:
        NetworkTrafficImage.__init__(self, fill, dim)
        self.packets = packets
        self.auto_dim = auto_dim
        self.matrix, self.binaries = self.__get_matrix_tiled(self.fill, self.dim, self.auto_dim, packets)
        del packets

    def __get_matrix_tiled(self, fill: int, dim: int, auto_dim: bool, packets: [Packet]):
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

        length = max(map(len, binaries))
        # Get dim of packet, using auto_dim uses the largest packet as dim reference
        if auto_dim:
            dim = int(np.ceil(np.sqrt(length)))

        result = []
        for x in binaries:
            x = x[: dim * dim]
            x = np.array(x + [fill] * (dim * dim - len(x)))
            x = x.reshape(dim, dim)
            result.append(x)

        # Get size of total image
        length_total = len(result)
        dim_total = int(np.ceil(np.sqrt(length_total)))
        # dim_total = 4

        # Create tiled image
        fh = self.__tile_images(result, dim_total, dim)
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