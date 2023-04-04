import fnmatch
import os

import pytest
from scapy.all import rdpcap

from heifip.extractor import FIPExtractor
from heifip.images.flow import FlowImage
from heifip.images.markovchain import (MarkovTransitionMatrixFlow,
                                       MarkovTransitionMatrixPacket)
from heifip.images.packet import PacketImage
from heifip.layers import PacketProcessorType

TEST_FOLDER = "./tests/pcaps"
OUTPUT_DIR = "./tests/images"


def get_files():
    assert os.path.exists(TEST_FOLDER)
    packets = []
    for root, dirnames, filenames in os.walk(TEST_FOLDER):
        for filename in fnmatch.filter(filenames, "*.pcap"):
            match = os.path.join(root, filename)
            sub_dir = match.replace(TEST_FOLDER, "")
            packets.append(rdpcap(match))
    return packets[0:5] # Otherwise we break Python...


@pytest.mark.parametrize('packet', get_files())
@pytest.mark.parametrize("auto_dim", [True, False])
@pytest.mark.parametrize("append", [True, False])
@pytest.mark.parametrize("fill", [0, 255])
@pytest.mark.parametrize("dim", [4, 16])
@pytest.mark.parametrize("width", [8, 16])
@pytest.mark.parametrize("tiled", [True, False])
@pytest.mark.parametrize(
    "min_packets_per_flow", [0, 4]
)
@pytest.mark.parametrize("max_image_dim", [0, 16])
@pytest.mark.parametrize("min_image_dim", [0, 16])
@pytest.mark.parametrize("remove_duplicates", [True, False])
@pytest.mark.parametrize(
    "preprocessing_type", [PacketProcessorType.HEADER, PacketProcessorType.NONE]
)
def test_extractor_flow(
    packet,
    auto_dim,
    append,
    fill,
    dim,
    width,
    tiled,
    min_packets_per_flow,
    max_image_dim,
    min_image_dim,
    remove_duplicates,
    preprocessing_type,
):
    extractor = FIPExtractor()
    extractor.create_image_from_packet(
        packet,
        preprocessing_type,
        FlowImage,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        0,
        remove_duplicates,
        dim,
        fill,
        width,
        tiled,
        auto_dim,
        append,
    )
    # TODO: Assert matrix... if functions worked fine

@pytest.mark.parametrize('packet', get_files())
@pytest.mark.parametrize(
    "min_packets_per_flow", [0, 4]
)
@pytest.mark.parametrize(
    "max_packets_per_flow", [0, 4]
)
@pytest.mark.parametrize("max_image_dim", [0, 16])
@pytest.mark.parametrize("min_image_dim", [0, 16])
@pytest.mark.parametrize("remove_duplicates", [True, False])
@pytest.mark.parametrize(
    "preprocessing_type", [PacketProcessorType.HEADER, PacketProcessorType.NONE]
)
def test_extractor_markovflow(
    packet,
    min_packets_per_flow,
    max_packets_per_flow,
    max_image_dim,
    min_image_dim,
    remove_duplicates,
    preprocessing_type,
):
    extractor = FIPExtractor()
    extractor.create_image_from_packet(
        packet,
        preprocessing_type,
        MarkovTransitionMatrixFlow,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        max_packets_per_flow,
        remove_duplicates,
    )
    # TODO: Assert matrix... if functions worked fine

@pytest.mark.parametrize('packet', get_files())
@pytest.mark.parametrize(
    "min_packets_per_flow", [0, 4]
)
@pytest.mark.parametrize("max_image_dim", [0, 16])
@pytest.mark.parametrize("min_image_dim", [0, 16])
@pytest.mark.parametrize("remove_duplicates", [True, False])
@pytest.mark.parametrize(
    "preprocessing_type", [PacketProcessorType.HEADER, PacketProcessorType.NONE]
)
def test_extractor_markovpacket(
    packet,
    min_packets_per_flow,
    max_image_dim,
    min_image_dim,
    remove_duplicates,
    preprocessing_type,
):
    extractor = FIPExtractor()
    extractor.create_image_from_packet(
        packet,
        preprocessing_type,
        MarkovTransitionMatrixPacket,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        0,
        remove_duplicates,
    )
    # TODO: Assert matrix... if functions worked fine

@pytest.mark.parametrize('packet', get_files())
@pytest.mark.parametrize("fill", [0, 255])
@pytest.mark.parametrize("dim", [4, 16])
@pytest.mark.parametrize("max_image_dim", [0, 16])
@pytest.mark.parametrize("min_image_dim", [0, 16])
@pytest.mark.parametrize("remove_duplicates", [True, False])
@pytest.mark.parametrize(
    "preprocessing_type", [PacketProcessorType.HEADER, PacketProcessorType.NONE]
)
def test_extractor_packet(
    packet,
    fill,
    dim,
    max_image_dim,
    min_image_dim,
    remove_duplicates,
    preprocessing_type,
):
    extractor = FIPExtractor()
    extractor.create_image_from_packet(
        packet,
        preprocessing_type,
        PacketImage,
        min_image_dim,
        max_image_dim,
        0,
        0,
        remove_duplicates,
        dim,
        fill,
        False
    )
    # TODO: Assert matrix... if functions worked fine

if __name__ == "__main__":
    pytest.main()
