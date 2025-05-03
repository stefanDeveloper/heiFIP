# heiFIB

**heiFIB** is a high-performance C++ implementation of a network traffic image generation pipeline originally developed in Python. It converts packet-level flow data into image representations using various encoding strategies, including grayscale matrices, tiled images, and Markov transition matrices.

## Features

- Support for multiple image encodings:
  - `FlowImage`
  - `FlowImageTiledFixed`
  - `FlowImageTiledAuto`
  - `PacketImage`
  - `MarkovTransitionMatrixFlow`
  - `MarkovTransitionMatrixPacket`
- Grayscale and multi-channel output support
- Optimized for batch processing and threading
- Seamless integration with OpenCV for image output

## Requirements

- C++17 or later
- [OpenCV](https://opencv.org/) (version 4.0+ recommended)
- CMake (version 3.10+)

## Build Instructions

```bash
git clone https://github.com/your-org/heiFIB.git
cd heiFIB
mkdir build && cd build
cmake ..
make -j$(nproc)
