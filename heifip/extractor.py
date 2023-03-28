import os

from PIL import Image as PILImage

from heifip.images.flow import FlowImage
from heifip.layers import PacketProcessor, PacketProcessorType


class FIPExtractor:
    def __init__(self):
        self.processor = PacketProcessor()
        self.images_created = []

    def create_image(
            self,
            input_file: str,
            preprocessing_type: PacketProcessorType = PacketProcessorType.NONE,
            min_image_dim: int = 0,
            max_image_dim: int = 0,
            min_packets_per_flow: int = 0,
            remove_duplicates: bool = False,
            width: str=128,
            append: bool=False,
            tiled: bool=True):

        assert os.path.isfile(input_file)

        packets = self.processor.read_packets(input_file, preprocessing_type)

        # when no file matches the preprocessing
        if len(packets) == 0 or len(packets) < min_packets_per_flow:
            return

        image = FlowImage(packets, width=width, append=append, tiled=tiled, auto_dim=True)
        flow_image = image.matrix

        if flow_image.shape[0] < min_image_dim or flow_image.shape[1] < min_image_dim:
            return

        if max_image_dim != 0 and (max_image_dim < flow_image.shape[0] or max_image_dim < flow_image.shape[1]):
            return

        if remove_duplicates:
            im_str = flow_image.tobytes()
            if im_str in self.images_created:
                return
            else:
                self.images_created.append(im_str)

        return PILImage.fromarray(image.matrix)

    def save_image(self, img, output_dir):
        if not os.path.exists(realpath(dirname(output_dir))):
            os.makedirs(realpath(dirname(output_dir)))
        im.save(f"{output_dir}_processed.png")
