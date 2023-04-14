import os

import numpy as np
from PIL import Image as PILImage
from scapy.all import Packet

from heifip.exceptions import FIPWrongParameterException
from heifip.images import NetworkTrafficImage
from heifip.images.flow import FlowImage
from heifip.images.flow_tiled_auto import FlowImageTiledAuto
from heifip.images.flow_tiled_fixed import FlowImageTiledFixed
from heifip.images.markovchain import (MarkovTransitionMatrixFlow,
                                       MarkovTransitionMatrixPacket)
from heifip.images.packet import PacketImage
from heifip.layers import PacketProcessor, PacketProcessorType
from heifip.layers.packet import FIPPacket


class FIPExtractor:
    def __init__(self):
        self.processor = PacketProcessor()
        self.images_created = []
    
    def verify(self, image, min_image_dim: int, max_image_dim: int, remove_duplicates: bool):
        if image.shape[0] < min_image_dim or image.shape[1] < min_image_dim:
            return False

        if max_image_dim != 0 and (max_image_dim < image.shape[0] or max_image_dim < image.shape[1]):
            return False

        # if remove_duplicates:
        #     im_str = image.tobytes()
        #     if im_str in self.images_created:
        #         return False 
        #     else:
        #         self.images_created.append(im_str)

        return True

    def create_image_from_file(
            self,
            input_file: str,
            preprocessing_type: PacketProcessorType = PacketProcessorType.NONE,
            image_type: NetworkTrafficImage = PacketImage,
            min_image_dim: int = 0,
            max_image_dim: int = 0,
            min_packets_per_flow: int = 0,
            max_packets_per_flow: int = 0,
            remove_duplicates: bool = False,
            *args
        ):

        assert os.path.isfile(input_file)

        packets = self.processor.read_packets_file(input_file, preprocessing_type)

        images = self.__create_matrix(
            packets,
            preprocessing_type,
            image_type,
            min_image_dim,
            max_image_dim,
            min_packets_per_flow,
            max_packets_per_flow,
            remove_duplicates,
            *args
        )

        return images

    def create_image_from_packet(
            self,
            packets: [FIPPacket],
            preprocessing_type: PacketProcessorType = PacketProcessorType.NONE,
            image_type: NetworkTrafficImage = PacketImage,
            min_image_dim: int = 0,
            max_image_dim: int = 0,
            min_packets_per_flow: int = 0,
            max_packets_per_flow: int = 0,
            remove_duplicates: bool = False,
            *args
        ):

        packets = self.processor.read_packets_packet(packets, preprocessing_type)

        images = self.__create_matrix(
            packets,
            preprocessing_type,
            image_type,
            min_image_dim,
            max_image_dim,
            min_packets_per_flow,
            max_packets_per_flow,
            remove_duplicates,
            *args
        )

        return images
    
    def __create_matrix(
            self,
            packets: [FIPPacket],
            preprocessing_type: PacketProcessorType = PacketProcessorType.NONE,
            image_type: NetworkTrafficImage = PacketImage,
            min_image_dim: int = 0,
            max_image_dim: int = 0,
            min_packets_per_flow: int = 0,
            max_packets_per_flow: int = 0,
            remove_duplicates: bool = False,
            *args
        ):
        images = []
        if image_type == FlowImage:
            # when no file matches the preprocessing
            if len(packets) == 0 or len(packets) < min_packets_per_flow:
                return images

            # cut packets when too many are there
            if max_packets_per_flow != 0 and len(packets) > max_packets_per_flow:
                packets = packets[:max_packets_per_flow]

            image = FlowImage(packets, *args)
            if self.verify(image.matrix, min_image_dim, max_image_dim, remove_duplicates):
                images.append(image.matrix)

        elif image_type == FlowImageTiledFixed:
            # when no file matches the preprocessing
            if len(packets) == 0 or len(packets) < min_packets_per_flow:
                return images

            # cut packets when too many are there
            if max_packets_per_flow != 0 and len(packets) > max_packets_per_flow:
                packets = packets[:max_packets_per_flow]

            image = FlowImageTiledFixed(packets, *args)
            if self.verify(image.matrix, min_image_dim, max_image_dim, remove_duplicates):
                images.append(image.matrix)

        elif image_type == FlowImageTiledAuto:
            # when no file matches the preprocessing
            if len(packets) == 0 or len(packets) < min_packets_per_flow:
                return images

            # cut packets when too many are there
            if max_packets_per_flow != 0 and len(packets) > max_packets_per_flow:
                packets = packets[:max_packets_per_flow]

            image = FlowImageTiledAuto(packets, *args)
            if self.verify(image.matrix, min_image_dim, max_image_dim, remove_duplicates):
                images.append(image.matrix)

        elif image_type  == PacketImage:

            for packet in packets:
                image = PacketImage(packet, *args)
                if self.verify(image.matrix, min_image_dim, max_image_dim, remove_duplicates):
                    images.append(image.matrix)

        elif image_type == MarkovTransitionMatrixFlow:
            # when no file matches the preprocessing
            if len(packets) == 0 or len(packets) < min_packets_per_flow:
                return images

            # cut packets when too many are there
            if max_packets_per_flow != 0 and len(packets) > max_packets_per_flow:
                packets = packets[:max_packets_per_flow]

            image = MarkovTransitionMatrixFlow(packets, *args)
            if self.verify(image.matrix, min_image_dim, max_image_dim, remove_duplicates):
                images.append(image.matrix)

        elif image_type == MarkovTransitionMatrixPacket:
            for packet in packets:
                image = MarkovTransitionMatrixPacket(packet, *args)
                if self.verify(image.matrix, min_image_dim, max_image_dim, remove_duplicates):
                    images.append(image.matrix)
        else:
            raise FIPWrongParameterException

        return images

    def save_image(self, img, output_dir):
        pil_img = PILImage.fromarray(img)
        if not os.path.exists(os.path.realpath(os.path.dirname(output_dir))):
            try:
                os.makedirs(os.path.realpath(os.path.dirname(output_dir)))
            except:
                pass
        pil_img.save(f"{output_dir}_processed.png")

    def convert(self, img, target_type_min, target_type_max, target_type):
        imin = img.min()
        imax = img.max()

        a = (target_type_max - target_type_min) / (imax - imin)
        b = target_type_max - a * imax
        new_img = (a * img + b).astype(target_type)
        return new_img