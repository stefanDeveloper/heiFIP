from heifip.extractor import FIPExtractor
from heifip.layers import PacketProcessorType
from heifip.images.flow import FlowImage

extractor = FIPExtractor()
imgs = extractor.create_image_from_file(
    "./tests/pcaps/dns-caa.pcap",
    PacketProcessorType.NONE,
    FlowImage,
    0, # min_image_dim
    0, # max_image_dim
    1, # min_packets
    0, # max_packets
    True, # remove_duplicates,
    8
    # 30, # dim
    # 0, # fill
    # True # auto_dim
)
print(imgs)
