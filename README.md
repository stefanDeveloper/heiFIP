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
    <a href="https://mybinder.org/v2/gh/heifip/heifip-tutorials/main?filepath=demo_notebook.ipynb">
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

The idea to create heiFIP rose while working with Deep Learning approaches for malware traffic classification.
Many papers show image representation, however, there is currently no official library to support reproducible data.

## Main Features

- **Different Images**: Currently, we support plain packet to byte representation, and flow to byte representation with one channel each. An image is created with same width and height for a quadratic representation.
  - **Flow Images** converts a set of packets into an image. It supports the following modifications:
    - **Max images dimension** allows you to specify the maximum image dimension. If the packet is larger than the specified size, it will cut the remaining pixel.
    - **Min image dimesion** allows you to specify the minimum image dimension. If the packet is smaller than the specified size, it fills the remaining pixel with 0.
    - **Remove duplicates** allows you to automatically remove same traffic.
    - **Append** each flow to each other or write each packet to a new row.
    - **Max packets per flow** allows you to specify the maximum number of packets per flow.
  - **Packet Image** converts a single packet into an image.
  - **Bidrectional Images** converts a bidirectional communication to an image.
- **Header** processing also you to customize header fields of different protocols. It aims to remove biasing fields.
  - **IPv4** and **IPv6**: tbd.
  - **TCP** and **UDP**: tbd.
  - **HTTP**: tbd.
  - **DNS**: tbd.
- **Remove Payload** options allows you to only work on header data.
- **Fast and flexible**: We rely on [Scapy]() for our image generation and header processing.
- **Machine learning orientation**: heiFIP aims to make Deep Learning approaches using network data as images reproducible and deployable. Using heiFIP as a common framework enables researches to test and verify their models.

## Examples

![SMB Connection](https://raw.githubusercontent.com/stefanDeveloper/heiFIP/main/examples/SMB.png?raw=true)

## Getting Started

Install our package using PyPi

```sh
pip install heifip
```

```sh
# Show help information
> fip extract -h
Starting FlowImageProcessor CLI
Usage: fip extract [OPTIONS]

Options:
  -rd, --remove_duplicates      Within a single output folder belonging to a
                                single input folder no duplicate images will
                                be produced if two inputs lead to the same
                                image
  -mp, --min_packets INTEGER    Minimum packets that a FlowImage needs to
                                have, 0=No minimum packets per flow
  -maxid, --max_im_dim INTEGER  Maximum dim ouput images can have, 0=No
                                maximum dim
  -mid, --min_im_dim INTEGER    Minimum dim ouput images need to have, 0=No
                                minimum dim
  -p, --preprocess TEXT         Applies a preprocessing to the input data:
                                none: No preprocessing payload: Only payload
                                data is used header: Preprocesses headers
                                (DNS,HTTP,IP,IPv6,TCP,UDP supported) to remove
                                some biasing data
  -t, --threads INTEGER         Number of parallel threads that can be used
  -r, --read PATH
  -w, --write PATH              Destination file path, stores result
                                [required]
  -h, --help                    Show this message and exit.

> fip extract -r /PATH/PCAPs -w /PATH/IMAGES
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

## Credits

[NFStream](https://github.com/nfstream/nfstream) for the inspiration of the `README.md` and workflow testing.

### Citation

Currently, we haven't publish any paper about our approach yet.
If you use heiFIP in a scientific publication, we would appreciate citations to the following article:

```latex
@software{Stefan_heiFIP_A_network_2023,
  author = {Stefan, Machmeier},
  month = {1},
  title = {{heiFIP: A network traffic image converter}},
  version = {1.0.0},
  year = {2023}
}
```

### Authors

The following people contributed to heiFIP:

- [Stefan Machmeier](https://github.com/stefanDeveloper): Creator
- [Manuel Trageser](https://github.com/maxi99manuel99): Header extraction and customization.

## License

This project is licensed under the  EUPL-1.2 [**License**](license) - see the License file for details

[license]: https://github.com/stefanDeveloper/heiFIP/blob/main/LICENSE