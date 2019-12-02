# Network connectivity visualizer on an ASCII worldmap

A scalable tool to visually display network traffic that listens via your network interface.

![Network connectivity worldmap example](https://raw.githubusercontent.com/f13rce/ConnectivityASCIIWorldmap/master/ExampleImage.png)

# Usage

After cloning, install the required packages:

``pip3 install -r requirements.txt``

Running the script:

``python3 showconnectivitymap.py``

# Requirements

Currently, this version requires Python3 and a Linux distro (or WSL) since os.system() is called a few times. Is still room for improvement.
