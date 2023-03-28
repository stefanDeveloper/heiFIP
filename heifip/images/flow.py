import binascii
import logging

import numpy as np
from scapy.all import Packet, raw

from heifip.images import NetworkTrafficImage


class FlowImage(NetworkTrafficImage):
    def __init__(
        self,
        packets,
        width=128,
        dim=8,
        fill=0,
        tiled=False,
        auto_dim=False,
        append=False,
    ) -> None:
        self.width = width
        self.packets = packets
        self.auto_dim = auto_dim
        self.fill = fill
        self.dim = dim
        self.matrix, self.binaries = (
            self.__get_matrix_tiled(self.dim, self.auto_dim, packets)
            if tiled
            else self.__get_matrix(append, packets)
        )
        del packets
        NetworkTrafficImage.__init__(self, fill, dim)

    def __tile_images(self, images, cols):
        """Tile images of same size to grid with given number of columns.

        Args:
            images (collection of ndarrays)
            cols (int): number of colums

        Returns:
            ndarray: stitched image
        """
        logging.debug("Building tiled image")
        images = iter(images)
        first = True
        rows = []
        i = 0
        while True:
            try:
                im = next(images)
                logging.debug(f"add image, shape: {im.shape}, type: {im.dtype}")
            except StopIteration:
                if first:
                    break
                else:
                    im = np.zeros_like(im)  # black background
            if first:
                row = im  # start next row
                first = False
            else:
                row = np.concatenate((row, im), axis=1)  # append to row
            i += 1
            if not i % cols:
                logging.debug(f"row done, shape: {row.shape}")
                rows.append(row)  # finished row
                first = True
        tiled = np.concatenate(rows)  # stitch rows
        return tiled

    def __get_matrix_tiled(self, dim: int, auto_dim: bool, packets: [Packet]):
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
            x = np.array(x + [self.fill] * (dim * dim - len(x)))
            x = x.reshape(dim, dim)
            result.append(x)

        # Get size of total image
        length_total = len(result)
        dim_total = int(np.ceil(np.sqrt(length_total)))

        # Create tiled image
        fh = self.__tile_images(result, dim_total)
        # Convert to int
        fh = np.uint8(fh)
        return fh, binaries

    def __get_matrix(self, append: bool, packets: list[Packet]):
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
            rn = len(fh) // self.width
            fh = np.reshape(fh[: rn * self.width], (-1, self.width))
        else:
            length = max(map(len, binaries))
            fh = np.array([xi + [255] * (length - len(xi)) for xi in binaries])

        fh = np.uint8(fh)

        return fh, binaries
