#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from masscan import __version__
from masscan import __author__

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst'), encoding='utf-8') as readme_file:
    long_description = readme_file.read()

setup(
    name='python-masscan',
    version=__version__,
    author=__author__,
    author_email='xsseroot@gmail.com',
    license='GPLv3+',
    keywords="masscan, portscanner",
    platforms=[
        "Operating System :: OS Independent",
        ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: System :: Networking :: Monitoring",
        ],
    packages=['masscan'],
    url='https://github.com/MyKings/python-masscan',
    long_description=long_description,
    long_description_content_type="text/markdown"
)
