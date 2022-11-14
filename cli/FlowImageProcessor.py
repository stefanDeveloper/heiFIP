try:
    import click
except ImportError:
    raise ImportError(
        "Please install Python dependencies: " "click, colorama (optional)."
    )

from fip.main import Runner
from . import CONTEXT_SETTINGS
from fip.version import __version__
from fip.packets import HTTPPacketProcessor

@click.version_option(version=__version__)
@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    click.secho("Starting FlowImageProcessor CLI")
    #if not config_file:
    #    config_file = click.get_app_dir("fip", force_posix=True)

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
    "-p",
    "--preprocess",
    "preprocessing_type",
    type=click.STRING,
    default="none",
    help="Applies a preprocessing to the input data:\n none: No preprocessing\n payload: Only payload data is used\n header: Preprocesses headers (DNS,HTTP,IP,IPv6,TCP,UDP supported) to remove some biasing data")
@cli.command(name="extract")
def extract(input_dir, output_dir, preprocessing_type):
    runner = Runner(7)
    runner.run(input_dir, output_dir, preprocessing_type, width=128, append=False, tiled=True)
