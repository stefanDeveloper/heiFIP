# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open("README.md") as f:
    README = f.read()

with open("LICENSE") as f:
    LICENSE = f.read()

with open("fip/version.py") as f:
    __version__ = ""
    exec(f.read())  # set __version__

setup(
    name="Flow Image Processor",
    version=__version__,
    description="A useful module to create packet flows into images",
    author="Stefan Machmeier",
    python_requires=">=3.7",
    author_email="stefan.machmeier@uni-heidelberg.de",
    maintainer="Stefan Machmeier",
    url="https://gitlab.urz.uni-heidelberg.de/it-sec/schwachstellenmanagement",
    long_description=README,
    include_package_data=True,
    packages=find_packages(),
    zip_safe=False,
    license=LICENSE,
    install_requires=[
        "pandas==1.4.3",
        "scapy==2.4.5",
        "image==1.5.33",
        "numpy==1.23.1",
        "click==8.1.3",
        "tqdm==4.64.1"
    ],
    extras_require={
        "cli": ["click==8.0.3", "click-help-colors==0.9.1"],
    },
    entry_points="""
      [console_scripts]
      fip=cli.FlowImageProcessor:cli
    """,
)

