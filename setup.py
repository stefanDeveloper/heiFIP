# -*- coding: utf-8 -*-
import sys
import platform
from setuptools import setup, find_packages

if (not sys.version_info[0] == 3) and (not sys.version_info[1] >= 6):
    sys.exit("Sorry, nfstream requires Python3.6+ versions.")

INSTALL_REQUIRES = ["scapy>=2.5.0",
                    "image>=1.5.33",
                    "numpy>=1.19.5",
                    "click>=8.1.3",
                    "tqdm>=4.64.1"]

if platform.python_implementation() == 'PyPy':  # This is mandatory to fix pandas issues with PyPy
    INSTALL_REQUIRES.append("pandas<=1.3.5")
else:
    INSTALL_REQUIRES.append("pandas>=1.3.5")

with open("README.md") as f:
    README = f.read()

with open("LICENSE") as f:
    LICENSE = f.read()

setup(
    name="heiFIP",
    version="0.0.1",
    description="A useful module to create packet flows into images",
    author="Stefan Machmeier",
    author_email="stefan.machmeier@uni-heidelberg.de",
    maintainer="Stefan Machmeier",
    url="https://github.com/stefanDeveloper/heiFIP",
    python_requires=">=3.7",
    long_description=README,
    long_description_content_type='text/markdown',
    include_package_data=True,
    packages=find_packages(),
    zip_safe=False,
    license=LICENSE,
    install_requires=INSTALL_REQUIRES,
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
      fip=heifip.cli:cli
    """,
)

