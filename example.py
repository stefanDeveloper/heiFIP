from heifip.extractor import FIPExtractor
from heifip.layers import PacketProcessorType
from heifip.images.flow import FlowImage

extractor = FIPExtractor()
img = extractor.create_image(input_file = './tests/pcaps/dns/dns-binds.pcap', preprocessing_type=PacketProcessorType.HEADER, image_type=FlowImage)
extractor.save_image(img[0], './test.png')