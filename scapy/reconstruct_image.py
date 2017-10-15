#!/usr/bin/env python3
import imghdr
import base64
import logging 
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

image = b''
packets = rdpcap('secret.pcap')

# extract and decode payloads from TCP packets
for p in packets:
	image += p.load
image = base64.b64decode(image)

# detect filetype and write image to file
ftype = imghdr.what(None, image)
ofile = open('output.' + ftype, 'w+b')
ofile.write(image)
ofile.close()
