import logging

import numpy as np
from scapy.all import Packet, chexdump, hexdump, raw

from heifip.images import NetworkTrafficImage


class MarkovTransitionMatrix(NetworkTrafficImage):
    def __init__(
        self,
    ) -> None:
        NetworkTrafficImage.__init__(self)

    def bit_array(self, packet):
        bytes_as_bits =  ''.join(format(byte, '08b') for byte in bytes(packet.packet))
        transition = []
        for i in range(0, len(bytes_as_bits), 4):
            transition.append(int(bytes_as_bits[i:i+4], 2))
        return transition

    def transition_matrix(self, transitions):
        n = 16

        M = [[0]*n for _ in range(n)]

        for (i,j) in zip(transitions,transitions[1:]):
            M[i][j] += 1

        #now convert to probabilities:
        for row in M:
            s = sum(row)
            if s > 0:
                row[:] = [f/s for f in row]
        return M

class MarkovTransitionMatrixFlow(MarkovTransitionMatrix):
    def __init__(
        self,
        packets: [Packet],
    ) -> None:
        MarkovTransitionMatrix.__init__(self)

        result = []
        for packet in packets:
            transition = self.bit_array(packet)
            m = self.transition_matrix(transition)
            result.append(np.array(m))
        
        # Create tiled image
        fh = self.__tile_images(result, 4, 16)

        # Convert to int
        self.matrix = fh
        del packets

    def __tile_images(self, images, cols, dim):
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

class MarkovTransitionMatrixPacket(MarkovTransitionMatrix):
    def __init__(
        self,
        packet: Packet,
    ) -> None:
        MarkovTransitionMatrix.__init__(self)

        transition = self.bit_array(packet)
        m = self.transition_matrix(transition)
        self.matrix = np.array(m)

        del packet
