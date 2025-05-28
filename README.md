# heiFIPCpp

**Flow & Packet Imaging and Matrix Extraction from PCAP**

A C++ command‑line tool to process network capture files (PCAP), generate various image representations (packet‑level, flow‑level, tiled, Markov transition matrices), and save outputs for further analysis or machine learning.

---

## Features

* **Packet Imaging**: Convert individual packets into grayscale images.
* **Flow Imaging**: Aggregate flows into images, with fixed or auto‑tiled layouts.
* **Markov Transition Matrices**: Compute byte‑level transition matrices at packet or flow granularity.
* **Custom Preprocessing**: Strip or transform headers before imaging.
* **Multi‑threaded**: Parallel processing across multiple CPU cores.
* **Extensible Architecture**: Add new image types or preprocessing pipelines via C++ classes.

---

## Requirements

* **C++ Compiler**: GCC ≥ 9.0, Clang ≥ 10, or MSVC 2019 with C++17 support.
* **CMake**: Version ≥ 3.15
* **PcapPlusPlus**: Installed system‑wide or built locally. ([https://github.com/seladb/PcapPlusPlus](https://github.com/seladb/PcapPlusPlus))
* **OpenSSL**: For MD5 hashing (libcrypto).
* **OpenCV**: Version ≥ 4.0 for image handling and saving (e.g., cv::imwrite).
* **pthread**: POSIX threads (Linux/macOS). Windows users require linking against `-lws2_32` and `-lIPHLPAPI`.

Optional:

* **getopt\_long**: For CLI parsing (provided by libc on Linux/macOS). Windows may need `getopt` replacement.

---

## Building

```bash
# Clone this repo
git clone https://github.com/yourusername/heiFIPCpp.git
cd heiFIP/heiFIP/

# Create build directory
mkdir build && cd build

# Configure (point at PcapPlusPlus if not in default locations)
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/opt/PcapPlusPlus

# Compile
make -j$(nproc)

# The executable 'heiFIPCpp' will be produced in build/
```

---

## Usage

```bash
./heiFIPCpp \
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
| `-h`, `--help`      | Show this help message                                         |

## Extending

To add a new image type:

1. Define a new `ImageArgs` struct in `extractor.cpp`.
2. Extend the `ImageType` enum.
3. Implement the conversion in `PacketProcessor::createImageFromPacket()`.
4. Update the CLI `--mode` parser to include your new type.

---

## License

This project is licensed under the EUPL-1.2 License - see the License file for details

---

*Happy packet‑to‑image transformations!*
