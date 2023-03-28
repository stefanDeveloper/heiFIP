import fnmatch
import os

import pytest

from heifip.extractor import FIPExtractor
from heifip.layers import PacketProcessorType

TEST_FOLDER = "./tests/pcaps"
OUTPUT_DIR = "./tests/images"

def get_files():
    assert os.path.exists(TEST_FOLDER)
    files = []
    for root, dirnames, filenames in os.walk(TEST_FOLDER):
        for filename in fnmatch.filter(filenames, "*.pcap"):
            match = os.path.join(root, filename)
            sub_dir = match.replace(TEST_FOLDER, "")
            files.append([match, f"{OUTPUT_DIR}/{sub_dir}"])
    return files

@pytest.mark.parametrize('filepath', get_files())
def test_extractor(filepath):
    extractor = FIPExtractor()
    extractor.create_image(filepath[0], PacketProcessorType.NONE)

@pytest.mark.parametrize('tiled', [True, False])
def test_extractor_tiled(tiled):
    files = get_files()
    extractor = FIPExtractor()
    extractor.create_image(files[0][0], PacketProcessorType.NONE, tiled=tiled)

@pytest.mark.parametrize('remove_duplicates', [True, False])
def test_extractor_remove_duplicates(remove_duplicates):
    files = get_files()
    extractor = FIPExtractor()
    extractor.create_image(files[0][0], PacketProcessorType.NONE, remove_duplicates=remove_duplicates)

@pytest.mark.parametrize('append', [True, False])
def test_extractor_append(append):
    files = get_files()
    extractor = FIPExtractor()
    extractor.create_image(files[0][0], PacketProcessorType.NONE, append=append)

@pytest.mark.parametrize('width', [8, 16, 32, 64, 128, 256])
def test_extractor_width(width):
    files = get_files()
    extractor = FIPExtractor()
    extractor.create_image(files[0][0], PacketProcessorType.NONE, width=width)

@pytest.mark.parametrize('min_image_dim', [0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256])
def test_extractor_min_image_dim(min_image_dim):
    files = get_files()
    extractor = FIPExtractor()
    extractor.create_image(files[0][0], PacketProcessorType.NONE, min_image_dim=min_image_dim)

@pytest.mark.parametrize('max_image_dim', [0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256])
def test_extractor_max_image_dim(max_image_dim):
    files = get_files()
    extractor = FIPExtractor()
    extractor.create_image(files[0][0], PacketProcessorType.NONE, max_image_dim=max_image_dim)

@pytest.mark.parametrize('min_packets_per_flow', [0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256])
def test_extractor_min_packets_per_flow(min_packets_per_flow):
    files = get_files()
    extractor = FIPExtractor()
    extractor.create_image(files[0][0], PacketProcessorType.NONE, min_packets_per_flow=min_packets_per_flow)


if __name__ == '__main__':
    pytest.main()
