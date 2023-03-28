try:
    import click
except ImportError:
    raise ImportError(
        "Please install Python dependencies: " "click, colorama (optional)."
    )

from heifip import CONTEXT_SETTINGS, __version__
from heifip.layers import PacketProcessorType
from heifip.main import Runner


@click.version_option(version=__version__)
@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    click.secho("Starting FlowImageProcessor CLI")


@click.option(
    "-w",
    "--write",
    "output_dir",
    type=click.Path(),
    required=True,
    help="Destination file path, stores result",
)
@click.option("-r", "--read", "input_dir", type=click.Path())
@click.option(
    "-t",
    "--threads",
    "num_threads",
    type=int,
    default=16,
    help="Number of parallel threads that can be used",
)
@click.option(
    "-p",
    "--preprocess",
    "preprocessing_type",
    default="NONE",
    type=click.Choice(
        list(map(lambda x: x.name, PacketProcessorType)), case_sensitive=False
    ),
    help="Applies a preprocessing to the input data:\n none: No preprocessing\n payload: Only payload data is used\n header: Preprocesses headers (DNS,HTTP,IP,IPv6,TCP,UDP supported) to remove some biasing data",
)
@click.option(
    "-mid",
    "--min_im_dim",
    "min_image_dim",
    type=int,
    default=0,
    help="Minimum dim ouput images need to have, 0=No minimum dim",
)
@click.option(
    "-maxid",
    "--max_im_dim",
    "max_image_dim",
    type=int,
    default=0,
    help="Maximum dim ouput images can have, 0=No maximum dim",
)
@click.option(
    "-mp",
    "--min_packets",
    "min_packets_per_flow",
    type=int,
    default=0,
    help="Minimum packets that a FlowImage needs to have, 0=No minimum packets per flow",
)
@click.option(
    "-rd",
    "--remove_duplicates",
    "remove_duplicates",
    is_flag=True,
    default=False,
    help="Within a single output folder belonging to a single input folder no duplicate images will be produced if two inputs lead to the same image",
)
@cli.command(name="extract")
def extract(
    input_dir,
    output_dir,
    num_threads,
    preprocessing_type,
    min_image_dim,
    max_image_dim,
    min_packets_per_flow,
    remove_duplicates,
):
    runner = Runner(num_threads)
    runner.run(
        input_dir,
        output_dir,
        preprocessing_type,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        remove_duplicates,
        width=128,
        append=False,
        tiled=True,
    )
