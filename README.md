![heiFIP Logo](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/assets/heiFIP_logo.png?raw=true)


--------------------------------------------------------------------------------

**heiFIP** stands for Heidelberg Flow Image Processor.
It is a tool designed to extract essential parts of packets and convert them into images for deep learning purposes.
heiFIP supports different formats and orientations.
Currently, we only support **offline** network data analysis.
However, we plan to adapt our library to support **online** network data too to enable live-probing of models.

<table>
<tr>
  <td><b>Latest Release</b></td>
  <td>
    <span style="background-color: #007BFF; color: white; padding: 4px 8px; border-radius: 4px;">Version 1.0</span>
  </td>
</tr>
<tr>
  <td><b>Project License</b></td>
  <td>
    <a href="https://github.com/stefanDeveloper/heifip/blob/main/LICENSE">
    <img src="https://img.shields.io/pypi/l/heifip?logo=gnu&style=for-the-badge&color=blue" alt="License" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Citation</b></td>
  <td>
    <a href="https://zenodo.org/badge/latestdoi/522472839">
    <img src="https://zenodo.org/badge/522472839.svg?style=for-the-badge" alt="Citation" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Continuous Integration</b></td>
  <td>
    <a href="https://github.com/stefanDeveloper/heifip/actions/workflows/build_test_linux.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/stefanDeveloper/heifip/build_test_linux.yml?branch=main&logo=linux&style=for-the-badge&label=linux" alt="Linux WorkFlows" />
    </a>
    <a href="https://github.com/stefanDeveloper/heifip/actions/workflows/build_test_macos.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/stefanDeveloper/heifip/build_test_macos.yml?branch=main&logo=apple&style=for-the-badge&label=macos" alt="MacOS WorkFlows" />
    </a>
  </td>
</tr>
</table>

## Table of Contents

- [**Main Features**](#main-features)
- [**Motivation**](#motivation)
- [**Examples**](#examples)
- [**Getting Started**](#getting-started)
  - [**Building from source**](#building-from-source)
- [**Citation**](#citation)
  - [**Credits**](#credits)
  - [**Authors**](#authors)
- [**License**](#license)

## Motivation

The idea to create heiFIP came from working with Deep Learning approaches to classify malware traffic on images. Many papers use image representation of network traffic, but reproducing their results was quite cumbersome. As a result, we found that there is currently no official library that supports reproducible images of network traffic. For this reason, we developed heiFIP to easily create images of network traffic and reproduce ML/DL results. Researchers can use this library as a baseline for their work to enable other researchers to easily recreate their findings.

## Main Features

- **Different Images**: Currently, we support plain packet to byte representation, and flow to byte representation with one channel each. An image is created with same width and height for a quadratic representation.
  - **Flow Images** converts a set of packets into an image. It supports the following modifications:
    - **Max images dimension** allows you to specify the maximum image dimension. If the packet is larger than the specified size, it will cut the remaining pixel.
    - **Min image dimesion** allows you to specify the minimum image dimension. If the packet is smaller than the specified size, it fills the remaining pixel with 0.
    - **Remove duplicates** allows you to automatically remove same traffic.
    - **Append** each flow to each other or write each packet to a new row.
    - **Tiled** each flow is tiled into a square image representation.
    - **Min packets per flow** allows you to specify the minimum number of packets per flow. If the total number of packets is too small, no image will be created.
    - **Max packets per flow** allows you to specify the maximum number of packets per flow. If the total number of packets is too great, the remaining images are discarded.
  - **Packet Image** converts a single packet into an image.
  - **Markov Transition Matrix Image**: converts a packet or a flow into a Markov representation.
- **Header** processing allows you to customize header fields of different protocols. It aims to remove biasing fields.
- **Remove Payload** options allows you to only work on header data.
- **Fast and flexible**: The main image precessing is in raw bytes inside the image classes while for the header preprocessing is PcapPlusPlus is used.
- **Machine learning orientation**: heiFIP aims to make Deep Learning approaches using network data as images reproducible and deployable. Using heiFIP as a common framework enables researches to test and verify their models.

## Examples

| Image Type | Description | Example |
|------------|-------------|---------|
| Packet | Converts a single packet into a square image. Size depends on the total length | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/packet.png?raw=true) |
| Flow | Converts a flow packet into a square image | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/flow-tiled.png?raw=true) |
| Markov Transition Matrix Packet | Converts a packet into a Markov Transition Matrix. Size is fixed to 16x16. | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/markov-packet.png?raw=true) |
| Markov Transition Matrix Flow | Converts a flow into a Markov Transition Matrix. It squares the image based on the number of packets | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/markov-flow.png?raw=true) |

## Requirements

* **C++ Compiler**: GCC ≥ 9.0, Clang ≥ 10, or MSVC 2019 with C++17 support.
* **CMake**: Version ≥ 3.14
* **vcpkg**: A C++ package manager to automatically download and build dependencies.

Dependencies managed automatically by `vcpkg`:
* **PcapPlusPlus**
* **OpenSSL**
* **OpenCV**
* **libpcap** (Linux/macOS) / `pthread`

## Building from source

We use `vcpkg` to manage all C++ dependencies for heiFIP smoothly. If you don't have `vcpkg` installed, follow their [official instructions](https://github.com/microsoft/vcpkg#quick-start-windows-linux-macos).

Ensure the `VCPKG_ROOT` environment variable is set to your `vcpkg` installation path (e.g., `export VCPKG_ROOT=~/vcpkg`).

```bash
# Clone this repo
git clone https://github.com/stefanDeveloper/heiFIP.git
cd heiFIP/heiFIP/

# Set up vcpkg
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT=$(pwd)/vcpkg

# Create build directory and run CMake using the vcpkg toolchain
# The toolchain will automatically read vcpkg.json and install dependencies!
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"

# Compile the project
cmake --build build -j$(nproc)

# The executables 'heiFIP' and 'main' will be produced in build/
```


## Getting Started

After installation the command line interface can be used to extract images from pcap files witht he following command
```bash
./heiFIP \
  --name HelloHeiFIP
  --input /path/to/capture.pcap \
  --output /path/to/outdir \
  --threads 4 \
  --processor HEADER \
  --mode FlowImageTiledAuto \
  --dim 16 \
  --apppend \
  --fill 0 \
  --min-dim 10 \
  --max-dim 2000 \
  --min-pkts 10 \
  --max-pkts 100 \
  --remove-dup
```

### Options
| Flag                | Description                                                    |
| ------------------- | -------------------------------------------------------------- |
| `-i`, `--input`     | Input PCAP file path                                           |
| `-o`, `--output`    | Output directory                                               |
| `-t`, `--threads`   | Number of worker threads (default: 1)                          |
| `-p`, `--processor` | Preprocessing: `NONE` or `HEADER`                              |
| `-m`, `--mode`      | Image type: `PacketImage`, `FlowImage`, `FlowImageTiledFixed`, |
|                     | `FlowImageTiledAuto`, `MarkovTransitionMatrixFlow`,            |
|                     | `MarkovTransitionMatrixPacket`                                 |
| `--dim`             | Base dimension for image (e.g. width/height in pixels)         |
| `--fill`            | Fill or padding value (0–255)                                  |
| `--cols`            | Number of columns (for tiled/fixed or Markov flow)             |
| `--auto-dim`        | Enable auto‑dimension selection (bool)                         |
| `--append`          | Enable auto‑dimension selection (bool)                         |
| `--min-dim`         | Minimum allowed image dimension                                |
| `--max-dim`         | Maximum allowed image dimension                                |
| `--min-pkts`        | Minimum packets per flow (for tiled/flow modes)                |
| `--max-pkts`        | Maximum packets per flow                                       |
| `--remove-dup`      | Remove duplicate flows/packets by hash                         |
| `--name`            | Filname of processed image                                     |
| `-h`, `--help`      | Show this help message                                         |

## Extending

To add a new image type:

1. Define a new `ImageArgs` struct in `extractor.cpp`.
2. Extend the `ImageType` enum.
3. Implement the conversion in `PacketProcessor::createImageFromPacket()`.
4. Update the CLI `--mode` parser to include your new type.

---

### Publications that use heiFIP

- S. Machmeier, M. Hoecker, V. Heuveline, "Explainable Artificial Intelligence for Improving a Session-Based Malware Traffic Classification with Deep Learning", in 2023 IEEE Symposium Series on Computational Intelligence (SSCI), Mexico-City, Mexico, 2023. https://doi.org/10.1109/SSCI52147.2023.10371980
- S. Machmeier, M. Trageser, M. Buchwald, and V. Heuveline, "A generalizable approach for network flow image representation for deep learning", in 2023 7th Cyber Security in Networking Conference (CSNet), Montréal, Canada, 2023. https://doi.org/10.1109/CSNet59123.2023.10339761

### Authors

The following people contributed to heiFIP:

- [Stefan Machmeier](https://github.com/stefanDeveloper): Creator
- [Manuel Trageser](https://github.com/maxi99manuel99): Header extraction and customization.
- [Henri Rebitzky](https://github.com/HenriRebitzky): Conversion from Python to C++

## License

This project is licensed under the  EUPL-1.2 [**License**](license) - see the License file for details

[license]: https://github.com/stefanDeveloper/heiFIP/blob/main/LICENSE