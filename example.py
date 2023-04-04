from heifip.extractor import FIPExtractor
from heifip.images.flow import FlowImage
from heifip.images.markovchain import (MarkovTransitionMatrixFlow,
                                       MarkovTransitionMatrixPacket)
from heifip.images.packet import PacketImage
from heifip.layers import PacketProcessorType

extractor = FIPExtractor()
img = extractor.create_image_from_file(
    "./tests/pcaps/http/bro.org.pcap",
    PacketProcessorType.NONE,
    MarkovTransitionMatrixPacket,
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
extractor.save_image(img[0], "./test2.jpg")
