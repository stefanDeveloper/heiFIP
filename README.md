![heiFIP Logo](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/assets/heiFIP_logo.png?raw=true)


--------------------------------------------------------------------------------

**heiFIP** stands for Heidelberg Flow Image Processor.
It is a tool designed to extract essential parts of packets and convert them into images for deep learning purposes.
heiFIP supports different formats and orientations.
Currently, we only support **offline** network data analysis.
However, we plan to adapt our library to support **online** network data too to enable live-probing of models.

<table>
<tr>
  <td><b>Live Notebook</b></td>
  <td>
    <a href="https://mybinder.org/v2/gh/stefanDeveloper/heiFIP-tutorials/HEAD?labpath=demo_notebook.ipynb">
    <img src="https://img.shields.io/badge/notebook-launch-blue?logo=jupyter&style=for-the-badge" alt="live notebook" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Latest Release</b></td>
  <td>
    <a href="https://pypi.python.org/pypi/heifip">
    <img src="https://img.shields.io/pypi/v/heifip.svg?logo=pypi&style=for-the-badge" alt="latest release" />
    </a>
  </td>
</tr>

<tr>
  <td><b>Supported Versions</b></td>
  <td>
    <a href="https://pypi.org/project/heifip/">
    <img src="https://img.shields.io/pypi/pyversions/heifip?logo=python&style=for-the-badge" alt="python3" />
    </a>
    <a href="https://pypi.org/project/heifip/">
    <img src="https://img.shields.io/badge/pypy-3.7%20%7C%203.8%20%7C%203.9-blue?logo=pypy&style=for-the-badge" alt="pypy3" />
    </a>
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
  <td><b>Continuous Integration</b></td>
  <td>
    <a href="https://github.com/stefanDeveloper/heifip/actions/workflows/build_test_linux.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/stefanDeveloper/heifip/build_test_linux.yml?branch=main&logo=linux&style=for-the-badge&label=linux" alt="Linux WorkFlows" />
    </a>
    <a href="https://github.com/stefanDeveloper/heifip/actions/workflows/build_test_macos.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/stefanDeveloper/heifip/build_test_macos.yml?branch=main&logo=apple&style=for-the-badge&label=macos" alt="MacOS WorkFlows" />
    </a>
    <a href="https://github.com/stefanDeveloper/heifip/actions/workflows/build_test_windows.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/stefanDeveloper/heifip/build_test_windows.yml?branch=main&logo=windows&style=for-the-badge&label=windows" alt="Windows WorkFlows" />
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
- **Header** processing allows you to customize header fields of different protocols. It aims to remove biasing fields. For more details look into [header.py](https://github.com/stefanDeveloper/heiFIP/blob/main/heifip/plugins/header.py)
- **Remove Payload** options allows you to only work on header data.
- **Fast and flexible**: We rely on [Scapy](https://github.com/secdev/scapy) for our sniffing and header processing. Image preparation is based on raw bytes.
- **Machine learning orientation**: heiFIP aims to make Deep Learning approaches using network data as images reproducible and deployable. Using heiFIP as a common framework enables researches to test and verify their models.

## Examples

| Image Type | Description | Example |
|------------|-------------|---------|
| Packet | Converts a single packet into a square image. Size depends on the total length | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/packet.png?raw=true) |
| Flow | Converts a flow packet into a square image | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/flow-tiled.png?raw=true) |
| Markov Transition Matrix Packet | Converts a packet into a Markov Transition Matrix. Size is fixed to 16x16. | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/markov-packet.png?raw=true) |
| Markov Transition Matrix Flow | Converts a flow into a Markov Transition Matrix. It squares the image based on the number of packets | ![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/markov-flow.png?raw=true) |

## Getting Started

Install our package using PyPi

```sh
pip install heifip
```
Now, you can use the integrate CLI:

```sh
> fip
Usage: fip [OPTIONS] COMMAND [ARGS]...

Options:
  --version   Show the version and exit.
  -h, --help  Show this message and exit.

Commands:
  extract
```

To extract images from PCAPs, we currently split the command into flow and packet:

```sh
> fip extract
Starting FlowImageProcessor CLI
Usage: fip extract [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  flow
  packet

# Show help information
> fip extract [flow/packet]-h
Starting FlowImageProcessor CLI
Usage: fip extract flow [OPTIONS]

Options:
  -w, --write PATH            Destination file path, stores result  [required]
  -r, --read PATH             [required]
  -t, --threads INTEGER       Number of parallel threads that can be used
                              [default: 4]
  --preprocess [NONE|HEADER]  Applies a preprocessing to the input data: none:
                              No preprocessing payload: Only payload data is
                              used header: Preprocesses headers
                              (DNS,HTTP,IP,IPv6,TCP,UDP supported) to remove
                              some biasing data  [default: NONE]
  --min_im_dim INTEGER        Minimum dim ouput images need to have, 0=No
                              minimum dim  [default: 0]
  --max_im_dim INTEGER        Maximum dim ouput images can have, 0=No maximum
                              dim  [default: 0]
  --remove_duplicates         Within a single output folder belonging to a
                              single input folder no duplicate images will be
                              produced if two inputs lead to the same image
  --min_packets INTEGER       Minimum packets that a FlowImage needs to have,
                              0=No minimum packets per flow  [default: 0]
  --max_packets INTEGER       Minimum packets that a FlowImage needs to have,
                              0=No minimum packets per flow  [default: 0]
  --append
  --tiled
  --width INTEGER             [default: 128]
  -h, --help                  Show this message and exit.

> fip extract flow -r /PATH/PCAPs -w /PATH/IMAGES
```

Import FIPExtractor to run it inside your program:

```python
extractor = FIPExtractor()
img = extractor.create_image('./test/pcaps/dns/dns-binds.pcap')
extractor.save_image(img, './test/pcaps/dns/dns-binds.pcap')
```

### Building from source

Simply run:

```
pip install .
```

### Publications that use heiFIP

- [A Generalizable Approach for Network Flow Image Representation for Deep Learning] - CSNet 23
- [Explainable artificial intelligence for improving a session-based malware traffic classification with deep learning] - SSCI 23


## Credits

[NFStream](https://github.com/nfstream/nfstream) for the inspiration of the `README.md` and workflow testing.

### Authors

The following people contributed to heiFIP:

- [Stefan Machmeier](https://github.com/stefanDeveloper): Creator
- [Manuel Trageser](https://github.com/maxi99manuel99): Header extraction and customization.

## License

This project is licensed under the  EUPL-1.2 [**License**](license) - see the License file for details

[license]: https://github.com/stefanDeveloper/heiFIP/blob/main/LICENSE