#!/usr/bin/env python3
import logging 
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
import sys
from scapy.all import *

try:
	if sys.argv[1] == '-h':
		print('usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]\n')
		print('A network sniffer that identifies basic vulnerabilities\n')
		print('optional arguments:')
		print('-h, --help    show this help message and exit')
		print('-i INTERFACE  Network interface to sniff on')
		print('-r PCAPFILE   A PCAP file to read')
except IndexError:
	print('not there yet')
