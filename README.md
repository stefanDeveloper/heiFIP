![heiFIP Logo](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/assets/heiFIP_logo.png?raw=true)


**heiFIP** (Heidelberg Flow Image Processor) is an open-source tool that transforms network traffic into image representations, tailored for Deep Learning research. It extracts key packet or flow data and converts it into structured images, enabling reproducible experiments in areas like malware classification, anomaly detection, and traffic analysis.


### 📊 Project Status
<table>
<tr>
  <td><b>Project License</b></td>
  <td>
    <a href="https://github.com/stefanDeveloper/heifip/blob/main/LICENSE">
    <img src="https://img.shields.io/pypi/l/heifip?logo=gnu&style=for-the-badge&color=blue" alt="License" />
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
- [**Building from source**](#building-from-source)
- [**Getting Started**](#getting-started)
- [**Authors**](#authors)
- [**License**](#license)

### Motivation

**heiFIP** was born from the challenge of reproducing Deep Learning research that visualizes network traffic as images—an increasingly popular method in malware and anomaly detection. While many papers leverage this technique, there was no unified tool or library to generate these traffic images in a consistent and reproducible way.

With heiFIP, we fill this gap by providing an open-source library designed to:

* Simplify the conversion of raw network traffic into image formats,
* Accelerate research reproducibility,
* Enable standardized benchmarks for ML/DL tasks involving network data.

Whether you're a researcher looking for a strong starting point or a developer seeking fast and flexible traffic visualization, **heiFIP makes network traffic image generation easy and reliable**.

## ✨ Key Features

* ### 📷 **Multiple Image Representations**

  * **Flow Images**: Convert sets of packets into image grids, with full control over:

    * Minimum & maximum image dimensions
    * Min/max packets per flow
    * Tiling, appending, or row-wise representation
    * Duplicate flow removal
  * **Packet Images**: Represent individual packets as fixed-size images.
  * **Markov Images**: Create Markov Transition Matrix (MTM) images from packet sequences or flows.

* ### 🧠 **ML/DL-Ready**

  * Designed for easy integration into Deep Learning pipelines.
  * Facilitates reproducible experiments by enforcing consistent traffic-to-image conversions.
  * Provides a reliable baseline for academic benchmarking.

* ### ⚙️ **Advanced Preprocessing**

  * **Header customization**: Strip or modify specific protocol headers to reduce dataset bias.
  * **Payload removal**: Focus solely on headers for privacy-sensitive or protocol-focused research.

* ### 🚀 **Performance & Flexibility**

  * Built on raw byte processing for speed.
  * Leverages **PcapPlusPlus** for robust packet and header manipulation.
  * Supports high-volume PCAP processing with configurable parameters.

## 📦 Examples

| Image Type | Description | Example |
|------------|-------------|---------|
| Packet | Converts a single packet into a square image. Size depends on the total length | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/heiFIP-cpp/examples/packet.png?raw=true) |
| Flow | Converts a flow packet into a square image | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/heiFIP-cpp/examples/flow-tiled.png?raw=true) |
| Markov Transition Matrix Packet | Converts a packet into a Markov Transition Matrix. Size is fixed to 16x16. | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/heiFIP-cpp/examples/markov-packet.png?raw=true) |
| Markov Transition Matrix Flow | Converts a flow into a Markov Transition Matrix. It squares the image based on the number of packets | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/heiFIP-cpp/examples/markov-flow.png?raw=true) |

## Requirements

* **C++ Compiler**: GCC ≥ 9.0, Clang ≥ 10, or MSVC 2019 with C++17 support.
* **CMake**: Version ≥ 3.14
* **PcapPlusPlus**: Installed system‑wide or built locally. ([https://github.com/seladb/PcapPlusPlus](https://github.com/seladb/PcapPlusPlus))
* **OpenSSL**: For SHA256 hashing (libcrypto).
* **OpenCV**: Version ≥ 4.0 for image handling and saving (e.g., cv::imwrite).
* **pthread**: POSIX threads (Linux/macOS). Windows users require linking against `-lws2_32` and `-lIPHLPAPI`.
* **libpcap**: PCAP Support (Linux/macOS)

Optional:

* **getopt\_long**: For CLI parsing (provided by libc on Linux/macOS). Windows may need `getopt` replacement.

## Building from source

>[!IMPORTANT]
> You can also download a pre-compiled version for easy use!.

```bash
# Clone this repo
git clone https://github.com/yourusername/heiFIPCpp.git
cd heiFIP/heiFIP/

# Create build directory
mkdir build && cd build

cmake ..

# We highly recommend that locating necessary dependencies is done manually since espically 
# Pcap Plus Plus is often not installed in standard locations. While we do use scripts to automatically detect 
# the necessary dependencies if those scripts fail you can specify the paths to the include directories of the header 
# files aswell as the paths to libaries manually like so. Also do not forget to specify all three of Pcap Plus Plus's
# libaries libCommon++, libPacket++, libPcap++. For OpenCV doing this manually while possible, due to number of links 
# necessary, is very difficult. Since OpenCV is configured for Cmake anyway this is unnecessary anyway. When using macOS
# you need to be very careful that the linked libraries are not Intel (x86_64) bottles, since if this happens the code
# will still be compiled as ARM64 but dynamically linking against x86_64 .dylib. This forces macOS to convert 
# back to ARM64 at runtime using Rosetta 2 which encures significant overhead. So if possible use a Linux distribution

cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DUSE_MANUAL_PCAPPLUSPLUS=ON \
  -DPcapPlusPlus_INCLUDE_DIRS="/opt/homebrew/Cellar/pcapplusplus/25.05/include" \
  -DPcapPlusPlus_LIBRARIES="/opt/homebrew/Cellar/pcapplusplus/25.05/lib/libCommon++.a\;/opt/homebrew/Cellar/pcapplusplus/25.05/lib/libPacket++.a\;/opt/homebrew/Cellar/pcapplusplus/25.05/lib/libPcap++.a" \
  -DUSE_MANUAL_OPENSSL=ON \
  -DOPENSSL_INCLUDE_DIR="/opt/homebrew/opt/openssl@3/include" \
  -DOPENSSL_CRYPTO_LIBRARY="/opt/homebrew/opt/openssl@3/lib/libcrypto.a"

# Compile
make -j$(nproc)

# or
cmake --build build

# The executable 'heiFIPCpp' will be produced in build/
```


## Getting Started

After installation the command line interface can be used to extract images from pcap files witht he following command
```bash
./heiFIPCpp \
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

## Publications that use heiFIP

- S. Machmeier, M. Hoecker, V. Heuveline, "Explainable Artificial Intelligence for Improving a Session-Based Malware Traffic Classification with Deep Learning", in 2023 IEEE Symposium Series on Computational Intelligence (SSCI), Mexico-City, Mexico, 2023. https://doi.org/10.1109/SSCI52147.2023.10371980
- S. Machmeier, M. Trageser, M. Buchwald, and V. Heuveline, "A generalizable approach for network flow image representation for deep learning", in 2023 7th Cyber Security in Networking Conference (CSNet), Montréal, Canada, 2023. https://doi.org/10.1109/CSNet59123.2023.10339761

## Authors

The following people contributed to heiFIP:

- [Stefan Machmeier](https://github.com/stefanDeveloper): Creator
- [Manuel Trageser](https://github.com/maxi99manuel99): Header extraction and customization.
- [Henri Rebitzky](https://github.com/HenriRebitzky): Coversion from python to c++

## License

This project is licensed under the  EUPL-1.2 [**License**](license) - see the License file for details

[license]: https://github.com/stefanDeveloper/heiFIP/blob/main/LICENSE