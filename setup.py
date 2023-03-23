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
    name="heiFIP",
    version=__version__,
    description="A useful module to create packet flows into images",
    author="Stefan Machmeier",
    python_requires=">=3.7",
    author_email="stefan.machmeier@uni-heidelberg.de",
    maintainer="Stefan Machmeier",
    url="https://github.com/stefanDeveloper/heiFIP",
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
    platforms=["Linux", "Mac OS-X", "Windows", "Unix"],
    classifiers=[
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Internet :: Log Analysis',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Scientific/Engineering :: Artificial Intelligence'
    ],
    extras_require={
        "cli": ["click==8.0.3", "click-help-colors==0.9.1"],
    },
    entry_points="""
      [console_scripts]
      fip=cli.FlowImageProcessor:cli
    """,
)

