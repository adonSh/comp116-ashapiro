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
USAGE = ('usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]\n\n'
		'A network sniffer that identifies basic vulnerabilities\n\n'
		'optional arguments:\n'
		'-h, --help    show this help message and exit\n'
		'-i INTERFACE  Network interface to sniff on\n'
		'-r PCAPFILE   A PCAP file to read\n')

def alert(incident):
	print(incident + '!')

def analyze(pcap):
	null = False
	fin = [ False, False, False ]
	xmas = False
	for packet in pcap:
		try:
			if packet[TCP].flags == 0:
				null = True
			if packet[TCP].flags == FIN:
				if fin[0]:
					fin[1] = True
				if fin[1]:
					fin[2] = True
				else:
					fin[0] = True
			if packet[TCP].flags & FIN & PSH & URG:
				xmas = True
		except IndexError:
			pass
	print('null: ' + str(null) + '\nfin: ' + str(fin[0] and fin[1] and fin[0]))

def sniff_live(iface):
	print('sniffing')

args = sys.argv[1:]
try:
	if args[0] == '-h' or args[0] == '--help':
		print(USAGE, end='')
	elif args[0] == '-i':
		try:
			sniff_live(args[1])
		except IndexError:
			print(USAGE, end='')
			exit(1)
	elif args[0] == '-r':
		try:
			print('analyzing ' + args[1] + ' ...')
			packets = rdpcap(args[1])
			analyze(packets)
		except IndexError:
			print('ierr')
			print(USAGE, end='')
			exit(1)
	else:
		print(USAGE, end='')
		exit(1)
except IndexError:
	print('sniffing on eth0')
