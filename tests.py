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
    print(filepath)
    extractor = FIPExtractor()
    extractor.create_image(filepath[0], filepath[1], PacketProcessorType.NONE)


if __name__ == '__main__':
    pytest.main()
