# Network connectivity visualizer on an ASCII worldmap

A scalable tool to visually display network traffic that listens via your network interface.

![Network connectivity worldmap example](https://raw.githubusercontent.com/f13rce/ConnectivityASCIIWorldmap/master/ExampleImage.png)

# Usage

After cloning, install the required packages:

``pip3 install -r requirements.txt --user``

Running the script:

``python3 showconnectivitymap.py``

Additional commands:

```
usage: showconnectivitymap.py [-h] [-i IFACE] [-r REFRESHRATE] [-s SPEED]

A scalable tool to visually display network traffic in form of an ASCII world
map that listens via your network interface. Please ensure that you have
permissions to read out the traffic of the used network interface.

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Interface to use, default is scapy's default interface
  -r REFRESHRATE, --refreshrate REFRESHRATE
                        Refresh rate of the worldmap. The value is X times per
                        second. Default = 10
  -s SPEED, --speed SPEED
                        Speed in percentage per refresh of the packets
                        traveling over this worldmap. The refresh rate alters
                        this as well. Default = 3
```

Make sure you have enough permissions to access the (default) network interface.

# Requirements

Currently, this version requires Python3 and a Linux distro (or WSL) since os.system() is called to fetch the width of the terminal.

# Comments

In this script there's a link to https://f13rce.net/ip.php to fetch the external IP address in case you were using a local IP. You can change this to any other web page. Copy over the ip.php file that only returns the page requester's IP to your web server and change the URL in the script.
