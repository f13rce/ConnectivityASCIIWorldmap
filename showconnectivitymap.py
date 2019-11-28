from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore
import os
from threading import Thread, Lock

###
# LAT (Y): 86 (up) -86 (down)
# LON (X): -180 (left) 180 (right)
###

# initialize colorama
init()

# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

ascii = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()\\//<>.,:;'\""

curSize = (-1, -1)

def convert_worldmap(width, height):
    # open image and convert to grayscale
    image = Image.open("worldmap.png").convert('L')
    # store dimensions
    W, H = image.size[0], image.size[1]
    # compute tile height based on aspect ratio and scale

def draw():
    while True:
        rows, cols = os.popen('stty size', 'r').read().split()
	if curSize[0] != rows or curSize[1] != cols:
		curSize = (rows, cols)
		convert_worldmap(rows, cols)

        print("R: {} | C: {}".format(rows, columns))

def sniff_packets(iface=None):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        sniff(filter="", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="", prn=process_packet, store=False)

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    ip = packet[IP].dst
    print(f"{GREEN} {ip}")
    #if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        #url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        #ip = packet[IP].src
        # get the request method
        #method = packet[HTTPRequest].Method.decode()
        #print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        #if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            #print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw

    sniff_thread = Thread(target=sniff_packets, args=(iface,))
    sniff_thread.start()
    #sniff_packets(iface)
    draw()
