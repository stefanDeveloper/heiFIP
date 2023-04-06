from heifip.extractor import FIPExtractor
from heifip.images.flow import FlowImage
from heifip.images.markovchain import (MarkovTransitionMatrixFlow,
                                       MarkovTransitionMatrixPacket)
from heifip.images.packet import PacketImage
from heifip.layers import PacketProcessorType

import numpy as np
import matplotlib.pyplot as plt

extractor = FIPExtractor()
imgs = extractor.create_image_from_file(
    "./tests/pcaps/http/bro.org.pcap",
    PacketProcessorType.NONE,
    MarkovTransitionMatrixFlow,
    0,
    0,
    0,
    16,
    # True,
    # 8,
    # 0,
    # 128,
    # True,
    # True,
    # True
)
# extractor.save_image(img[0], "./test2.jpg")
# fig = plt.figure(figsize=(16, 16))
# columns = 4
# rows = 4
# for i in range(1, columns*rows +1):
#     fig.add_subplot(rows, columns, i)
#     plt.ylabel("Y")
#     plt.xlabel("X")
#     plt.imshow(imgs[i])
# plt.savefig('test.pdf', dpi=fig.dpi)

plt.imshow(imgs[0])
plt.savefig('test.pdf')
