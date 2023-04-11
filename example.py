import matplotlib.pyplot as plt
import numpy as np

from heifip.extractor import FIPExtractor
from heifip.images.flow import FlowImage
from heifip.images.flow_tiled_auto import FlowImageTiledAuto
from heifip.images.flow_tiled_fixed import FlowImageTiledFixed
from heifip.images.markovchain import (MarkovTransitionMatrixFlow,
                                       MarkovTransitionMatrixPacket)
from heifip.images.packet import PacketImage
from heifip.layers import PacketProcessorType

extractor = FIPExtractor()
imgs = extractor.create_image_from_file(
    "/home/smachmeier/data/USTC-TFC2016-master/2_Session/AllLayers/FTP-ALL/FTP.pcap.TCP_1-1-221-163_51670_1-2-197-24_21.pcap",
    PacketProcessorType.NONE,
    MarkovTransitionMatrixFlow,
    0, # min_image_dim
    0, # max_image_dim
    3, # min_packets
    0, # max_packets
    True, # remove_duplicates,
    8
    # 30, # dim
    # 0, # fill
    # True # auto_dim
)
i = 0
for img in imgs:
    extractor.save_image(img, f"/home/smachmeier/Documents/projects/heiFIP/data/benign/{i}.png")
    i += 1

# fig = plt.figure(figsize=(16, 16))
# columns = 4
# rows = 4
# for i in range(1, columns*rows +1):
#     fig.add_subplot(rows, columns, i)
#     plt.ylabel("Y")
#     plt.xlabel("X")
#     plt.imshow(imgs[i])
# plt.savefig('test.pdf', dpi=fig.dpi)

# plt.imshow(imgs[0])
# plt.savefig('test.pdf')
