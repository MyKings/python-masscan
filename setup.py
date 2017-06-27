#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from distutils.core import setup, Extension

masscan = Extension('masscan', sources=['masscan/masscan.py', 'masscan/__init__.py', 'masscan/example.py'])

from masscan import __version__
from masscan import __author__

# Install : python setup.py install
# Register : python setup.py register

#  platform = 'Unix',


setup(
    name='python-masscan',
    version=__version__,
    author=__author__,
    author_email='xsseroot@gmail.com',
    license='LICENSE',
    keywords="masscan, portscanner",
    # Get more strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    platforms=[
        "Operating System :: OS Independent",
        ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
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
    bugtrack_url='https://github.com/MyKings/python-masscan',
    description='This is a python class to use masscan and access scan results from python2',
    # long_description=open('README.md').read() + "\n" + open('CHANGELOG.md').read(),
)
