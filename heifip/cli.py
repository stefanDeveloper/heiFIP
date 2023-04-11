try:
    import click
except ImportError:
    raise ImportError(
        "Please install Python dependencies: " "click, colorama (optional)."
    )

from heifip import CONTEXT_SETTINGS, __version__
from heifip.images import NetworkTrafficImage
from heifip.images.flow import FlowImage
from heifip.images.flow_tiled_auto import FlowImageTiledAuto
from heifip.images.flow_tiled_fixed import FlowImageTiledFixed
from heifip.images.markovchain import (MarkovTransitionMatrixFlow,
                                       MarkovTransitionMatrixPacket)
from heifip.images.packet import Packet
from heifip.layers import PacketProcessorType
from heifip.main import Runner


def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options


@click.version_option(version=__version__)
@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    click.secho("Starting FlowImageProcessor CLI")


_extract_options = [
    click.option(
        "-w",
        "--write",
        "output_dir",
        type=click.Path(),
        required=True,
        help="Destination file path, stores result.",
    ),
    click.option("-r", "--read", "input_dir", required=True, type=click.Path()),
    click.option(
        "-t",
        "--threads",
        "num_threads",
        type=int,
        default=4,
        help="Number of parallel threads that can be used.",
    ),
    click.option(
        "--preprocess",
        "preprocessing_type",
        default="NONE",
        type=click.Choice(
            list(map(lambda x: x.name, PacketProcessorType)), case_sensitive=False
        ),
        help="Applies a preprocessing to the input data:\n none: No preprocessing\n payload: Only payload data is used\n header: Preprocesses headers (DNS,HTTP,IP,IPv6,TCP,UDP supported) to remove some biasing data.",
    ),
    click.option(
        "--min-im-dim",
        "min_image_dim",
        type=int,
        default=0,
        help="Minimum dim ouput images need to have, 0=No minimum dim.",
    ),
    click.option(
        "--max-im-dim",
        "max_image_dim",
        type=int,
        default=0,
        help="Maximum dim ouput images can have, 0=No maximum dim.",
    ),
    click.option(
        "--remove-duplicates",
        "remove_duplicates",
        is_flag=True,
        default=False,
        help="Within a single output folder belonging to a single input folder no duplicate images will be produced if two inputs lead to the same image.",
    ),
]

_flow_options = [
    click.option(
        "--min-packets",
        "min_packets_per_flow",
        type=int,
        default=0,
        help="Minimum packets that a FlowImage needs to have, 0=No minimum packets per flow.",
    ),
    click.option(
        "--max-packets",
        "max_packets_per_flow",
        type=int,
        default=0,
        help="Minimum packets that a FlowImage needs to have, 0=No minimum packets per flow.",
    ),
]

_image_options = [
    click.option(
        "--dim",
        "dim",
        type=int,
        default=8,
        help="Dimension of the image.",
    ),
    click.option(
        "--fill",
        "fill",
        type=int,
        default=0,
        help="Fills remaining parts of the array of the image. Important: value has to be between 0-255.",
    ),
]

_auto_dim_options = [
    click.option(
        "--auto-dim",
        "auto_dim",
        is_flag=True,
        default=False,
        help="Automatically adjust size of image based on the length of the packet/s.",
    ),
]


@cli.group(name="extract", context_settings={"show_default": True})
def extract():
    click.secho("Extract FlowImageProcessor CLI")


@extract.command(name="packet")
@add_options(_extract_options)
@add_options(_flow_options)
@add_options(_image_options)
@add_options(_auto_dim_options)
def extract_packet_image(
    input_dir,
    output_dir,
    num_threads,
    preprocessing_type,
    min_image_dim,
    max_image_dim,
    min_packets_per_flow,
    max_packets_per_flow,
    remove_duplicates,
    dim,
    fill,
    auto_dim,
):
    """Extracts each packet from PCAP file and converts it into a single image representation."""
    runner = Runner(num_threads)
    runner.run(
        input_dir,
        output_dir,
        preprocessing_type,
        PacketImage,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        max_packets_per_flow,
        remove_duplicates,
        dim,
        fill,
        auto_dim,
    )


@extract.command(name="flow")
@add_options(_extract_options)
@add_options(_flow_options)
@add_options(_image_options)
@click.option(
    "--append",
    "append",
    is_flag=True,
    default=False,
    help="",
)
def extract_flow_image(
    input_dir,
    output_dir,
    num_threads,
    preprocessing_type,
    min_image_dim,
    max_image_dim,
    min_packets_per_flow,
    max_packets_per_flow,
    remove_duplicates,
    dim,
    fill,
    append,
):
    """Extracts a list of packets from PCAP file and converts it into an image. You can either append each packet or write each packet into a new line."""
    runner = Runner(num_threads)
    runner.run(
        input_dir,
        output_dir,
        preprocessing_type,
        FlowImage,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        max_packets_per_flow,
        remove_duplicates,
        dim,
        fill,
        append,
    )


@extract.command(name="flow-tiled-fixed")
@add_options(_extract_options)
@add_options(_flow_options)
@add_options(_image_options)
@click.option(
    "--cols",
    "cols",
    type=int,
    default=4,
    help="Number of columns for quadratic representation.",
)
def extract_flow_tiled_fixed_image(
    input_dir,
    output_dir,
    num_threads,
    preprocessing_type,
    min_image_dim,
    max_image_dim,
    min_packets_per_flow,
    max_packets_per_flow,
    remove_duplicates,
    dim,
    fill,
    cols,
):
    """Extracts packets from PCAP file and converts all packets into a single quadratic image based on the number of columns. If more packets are given than the total size of cols*cols, only the first n given packets are used."""
    runner = Runner(num_threads)
    runner.run(
        input_dir,
        output_dir,
        preprocessing_type,
        FlowImageTiledFixed,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        max_packets_per_flow,
        remove_duplicates,
        dim,
        fill,
        cols,
    )


@extract.command(name="flow-tiled-auto")
@add_options(_extract_options)
@add_options(_flow_options)
@add_options(_image_options)
@add_options(_auto_dim_options)
def extract_flow_tiled_fixed_image(
    input_dir,
    output_dir,
    num_threads,
    preprocessing_type,
    min_image_dim,
    max_image_dim,
    min_packets_per_flow,
    max_packets_per_flow,
    remove_duplicates,
    dim,
    fill,
    cols,
):
    """Extracts packets from PCAP file and converts all packets into a single quadratic image. It adjust the size based on the total amount of packets."""
    runner = Runner(num_threads)
    runner.run(
        input_dir,
        output_dir,
        preprocessing_type,
        FlowImageTiledAuto,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        max_packets_per_flow,
        remove_duplicates,
        dim,
        fill,
        cols,
    )


@extract.command(name="markov-flow")
@add_options(_extract_options)
@add_options(_flow_options)
@click.option(
    "--cols",
    "cols",
    type=int,
    default=4,
    help="Number of columns for quadratic representation.",
)
def extract_markov_image(
    input_dir,
    output_dir,
    num_threads,
    preprocessing_type,
    min_image_dim,
    max_image_dim,
    min_packets_per_flow,
    max_packets_per_flow,
    remove_duplicates,
    cols
):
    """Extracts packets from PCAP file and converts it into a quadractic Markov Transition Matrix."""
    runner = Runner(num_threads)
    runner.run(
        input_dir,
        output_dir,
        preprocessing_type,
        MarkovTransitionMatrixFlow,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        max_packets_per_flow,
        remove_duplicates,
        cols
    )

@extract.command(name="markov-packet")
@add_options(_extract_options)
@add_options(_flow_options)
def extract_markov_image(
    input_dir,
    output_dir,
    num_threads,
    preprocessing_type,
    min_image_dim,
    max_image_dim,
    min_packets_per_flow,
    max_packets_per_flow,
    remove_duplicates,
):
    """Extracts packets from PCAP file and converts it into a quadractic Markov Transition Matrix."""
    runner = Runner(num_threads)
    runner.run(
        input_dir,
        output_dir,
        preprocessing_type,
        MarkovTransitionMatrixFlow,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        max_packets_per_flow,
        remove_duplicates,
    )


if __name__ == "__main__":
    cli()
