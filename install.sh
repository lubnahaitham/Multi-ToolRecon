#!/bin/bash

# install.sh
# ==========
# A single script to install both apt-get and pip3 dependencies
# for the multi-threaded recon tool.

# 1) Update apt and install system packages
sudo apt-get update

# System packages
sudo apt-get install -y \
  theharvester \
  whois \
  dnsmap \
  wafw00f \
  unicornscan \
  nmap \
  testssl.sh \
  amass \
  dnsenum \
  metagoofil \
  exiftool

# 2) Install Python packages via pip
pip3 install colorama tabulate sublist3r dirsearch

echo "All packages installed!"
