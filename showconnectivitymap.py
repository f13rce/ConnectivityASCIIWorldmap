# Worldmap network connectivity

# Imports
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet

from termcolor import colored

import os
import sys

from threading import Thread, Lock

import worldmap

import json

import time

###
# LAT (Y): 86 (up) -86 (down)
# LON (X): -180 (left) 180 (right)
###

latRange = 86
lonRange = 180

worldMap = None
curSize = (-1, -1)

ipGeos = []
activePackets = []

class Packet:
    src = ""
    dst = ""
    geoFrom = (0, 0)
    geoTo = (0, 0)
    pct = 0
    size = 0 # in ascii (= ceil(KB / 100))
    type = "tcp" # "udp", etc

def replace_str_index(text,index=0,replacement=''):
    return "{}{}{}".format(text[:int(index)], replacement, text[int(index)+1:])
    #return "{text[:int(index)]}{replacement}{text[int(index)+1:]}"

def get_geolocation(ip):
    global ipGeos

    for entry in ipGeos:
        if entry[0] == ip:
            return entry[1]

    url = "https://ipinfo.io/{}/json".format(ip)
    os.system("rm json 2>/dev/null")
    os.system("wget {} 2>/dev/null".format(url))
    #os.system("wget {}".format(url))

    file = open("json", "r")
    data = json.load(file)

    os.system("rm json 2>/dev/null")

    data = data["loc"].split(",")
    data = (float(data[0]), float(data[1]))

    ipGeos.append( (ip, data) )
    #print(data)

    return data

def geo_to_ascii(geo):
    global worldMap
    if worldMap == None:
        return None

    #print("WMP GEO TO ASCII: {}, {}".format(len(worldMap), len(worldMap[0])))
    #print("latRange: {} | lonRange: {} | geo: {}".format(latRange, lonRange, repr(geo)))
    lat = int(len(worldMap) - len(worldMap) / (latRange * 2) * (geo[0] + latRange))
    lon = int(len(worldMap[0]) / (lonRange * 2) * (geo[1] + lonRange))
    #print("THEREFORE: {}, {}".format(lat, lon))
    return (lat, lon)

def draw():
    global curSize
    global worldMap
    while True:
        rows, cols = os.popen('stty size', 'r').read().split()
        rows = int(rows)
        cols = int(cols)
        if curSize[0] != rows or curSize[1] != cols:
            curSize = (rows, cols)
            worldMap = worldmap.covertImageToAscii("worldmap.png", cols, 0.43, False)

        worldMapTemp = worldMap.copy()
        toRemove = []
        for i in range(len(activePackets)):
            activePackets[i].pct += 7

            if activePackets[i].pct >= 100:
                toRemove.append(i)
                continue

            deltaLat = activePackets[i].geoTo[0] - activePackets[i].geoFrom[0]
            deltaLon = activePackets[i].geoTo[1] - activePackets[i].geoFrom[1]
            newGeoLat = activePackets[i].geoFrom[0] + (deltaLat / 100 * activePackets[i].pct)
            newGeoLon = activePackets[i].geoFrom[1] + (deltaLon / 100 * activePackets[i].pct)
            pos = geo_to_ascii((newGeoLat, newGeoLon))
            worldMapTemp[pos[0]] = replace_str_index(worldMapTemp[pos[0]], pos[1], "#")

        i = len(toRemove) - 1
        while i >= 0:
            activePackets.pop(i)
            i -= 1

        os.system("clear")
        for row in worldMapTemp:
            for char in row:
                if char == "#":
                    sys.stdout.write(colored(char, "red"))
                else:
                    sys.stdout.write(colored(char, "green"))
                    #sys.stdout.write(char)
            sys.stdout.write("\n")
            #print(colored(row, "blue"))
            #print(f"{BLUE}{row}{BLUE}")
        time.sleep(0.5)

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

    #print(repr(packet))
    try:
        ip = packet[IP].dst
        #print(f"{GREEN} {ip}")

        p = Packet()
        p.src = packet[IP].src
        p.dst = packet[IP].dst
        p.geoFrom = get_geolocation(p.src)
        p.geoTo = get_geolocation(p.dst)
        p.pct = 0
        p.size = 1 #packet[IP].size / 100 #or something...

        #print(repr(p))

        global activePackets
        activePackets.append(p)
    except:
        pass

    #p.type = packet[IP].type

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
    #global ownIP

    import argparse
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")

    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw

    #ownIP = ni.ifaddresses('eth0')[AF_INET][0]['addr']

    sniff_thread = Thread(target=sniff_packets, args=(iface,))
    sniff_thread.start()

    #sniff_packets(iface)
    draw()

    #get_geolocation("188.166.66.37")
