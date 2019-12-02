# Worldmap network connectivity

# Imports
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
import requests

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

paddingFix = (-5, -13) # Geo coords, fixes the worldmap placement

bogonIPs = []
externalIP = ""

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

def get_geolocation(ip):
    global externalIP
    global ipGeos
    global bogonIPs

    # Replace internal IP with external if applicable
    for bogonIP in bogonIPs:
        if ip == bogonIP:
            ip = externalIP
            break

    # Check if we already have this in cache
    for entry in ipGeos:
        if entry[0] == ip:
            return (entry[1][0] + paddingFix[0], entry[1][1] + paddingFix[1])

    # Fetch geo from this site
    url = "https://ipinfo.io/{}/json".format(ip)
    r = requests.get(url)
    data = json.loads(r.content.decode("utf-8"))

    # Check if this is a private IP address. If so, skip it.
    if "bogon" in data:
        if externalIP == "":
            externalIP = requests.get("https://f13rce.net/ip.php").content.decode("utf-8")
        bogonIPs.append(ip)
        return get_geolocation(externalIP)

    if not data.get("loc"):
        return None

    data = data["loc"].split(",")
    data = (float(data[0]), float(data[1]))

    # Add to cache for next time
    ipGeos.append( (ip, data) )

    return (data[0] + paddingFix[0], data[1] + paddingFix[1])

def geo_to_ascii(geo):
    global worldMap
    if worldMap == None:
        return None

    lat = int(len(worldMap) - len(worldMap) / (latRange * 2) * (geo[0] + latRange))
    lon = int(len(worldMap[0]) / (lonRange * 2) * (geo[1] + lonRange))

    return (lat, lon)

def draw(refreshRate, packetSpeed):
    global curSize
    global worldMap

    refreshTime = 1.0 / refreshRate

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
            activePackets[i].pct += packetSpeed

            if activePackets[i].pct >= 100:
                toRemove.append(i)
                continue

            # Packet
            deltaLat = activePackets[i].geoTo[0] - activePackets[i].geoFrom[0]
            deltaLon = activePackets[i].geoTo[1] - activePackets[i].geoFrom[1]
            newGeoLat = activePackets[i].geoFrom[0] + (deltaLat / 100 * activePackets[i].pct)
            newGeoLon = activePackets[i].geoFrom[1] + (deltaLon / 100 * activePackets[i].pct)
            pos = geo_to_ascii((newGeoLat, newGeoLon))
            worldMapTemp[pos[0]] = replace_str_index(worldMapTemp[pos[0]], pos[1], "#")

            # DST
            pos = geo_to_ascii(activePackets[i].geoFrom)
            worldMapTemp[pos[0]] = replace_str_index(worldMapTemp[pos[0]], pos[1], "@")

            # DST
            pos = geo_to_ascii(activePackets[i].geoTo)
            worldMapTemp[pos[0]] = replace_str_index(worldMapTemp[pos[0]], pos[1], "@")

        i = len(toRemove) - 1
        while i >= 0:
            activePackets.pop(i)
            i -= 1

        # Prepare what to print
        toWrite = ""
        for row in worldMapTemp:
            for char in row:
                if char == "#":
                    toWrite += colored(char, "red")
                elif char == "@":
                    toWrite += colored(char, "yellow")
                else:
                    toWrite += colored(char, "green")
            toWrite += "\n"

        # Clear screen and print
        os.system('cls' if os.name == 'nt' else 'clear')
        os.write(1, toWrite.encode())
        sys.stdout.flush()

        # Until next time!
        time.sleep(refreshTime)

def sniff_packets(iface=None):
    """
    Sniff packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    if iface:
        sniff(filter="", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="", prn=process_packet, store=False)

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """

    ip = packet[IP].src
    geoFrom = get_geolocation(ip)

    # Sometimes the [IP] header is not found - then we can skip it.
    try:
        ip = packet[IP].dst

        p = Packet()
        p.src = packet[IP].src
        p.dst = packet[IP].dst
        p.geoFrom = get_geolocation(p.src)
        p.geoTo = get_geolocation(p.dst)
        p.pct = 0
        p.size = 1 #packet[IP].size / 100 #or something...

        if p.geoFrom == None or p.geoTo == None:
            return

        global activePackets
        activePackets.append(p)
    except:
        pass

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="A scalable tool to visually display network traffic in form of an ASCII world map that listens via your network interface.\n" \
                                                 + "Please ensure that you have permissions to read out the traffic of the used network interface.")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")

    parser.add_argument("-r", "--refreshrate", help="Refresh rate of the worldmap. The value is X times per second. Default = 10")
    parser.add_argument("-s", "--speed", help="Speed in percentage per refresh of the packets traveling over this worldmap. The refresh rate alters this as well. Default = 3")

    # parse arguments
    args = parser.parse_args()
    iface = args.iface

    rr = 10.0
    if args.refreshrate:
        if float(args.refreshrate) == 0:
            sys.exit("Refresh rate cannot be 0! This will cause a division by 0.")
        rr = float(args.refreshrate)

    spd = 3.0
    if args.speed:
        spd = float(args.speed)

    # Start sniffer
    sniff_thread = Thread(target=sniff_packets, args=(iface,))
    sniff_thread.start()

    # Draw results in the meantime
    draw(rr, spd)
