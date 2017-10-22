#!/usr/bin/env python2.7
from __future__ import print_function
import sys
from scapy.all import *

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def usage():
	return ('usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]\n\n'
			'A network sniffer that identifies basic vulnerabilities\n\n'
			'optional arguments:\n'
			'-h, --help    show this help message and exit\n'
			'-i INTERFACE  Network interface to sniff on\n'
			'-r PCAPFILE   A PCAP file to read\n')

def alert(incident):
	print(incident + '!')

def analyze(pcap):
	null = False
	fin = False
	xmas = False
	for i in range(len(pcap)):
		try:
			if pcap[i][TCP].flags == 0 and pcap[i-2][TCP].flags == 0:
				null = True
		except IndexError:
			pass

def sniff_live(iface):
	print('sniffing')

args = sys.argv[1:]
try:
	if args[0] == '-h' or args[0] == '--help':
		print(usage(), end='')
	elif args[0] == '-i':
		try:
			sniff_live(args[1])
		except IndexError:
			print(usage(), end='')
			exit(1)
	elif args[0] == '-r':
		try:
			print('analyzing ' + args[1] + '...')
			packets = rdpcap(args[1])
			analyze(packets)
		except IndexError:
			print('ierr')
			print(usage(), end='')
			exit(1)
except IndexError:
	print('sniffing on eth0')
