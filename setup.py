###############################################################################
#          Copyright (c) 2022 Rockwell Automation Technologies, Inc.          #
#                            All rights reserved.                             #
###############################################################################
"""
Setup for ecs all.
"""
from setuptools import setup

setup(
    name='scapy-cip-enip',
    version='0.0.1',
    packages=['scapy_enip',
              'scapy_cip_enip_common', ],
    install_requires=["hexdump"])
