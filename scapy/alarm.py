#!/usr/bin/env python2.7
from __future__ import print_function
import sys
import base64
from scapy.all import *

# CONSTANTS
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
	null = 0
	fin = 0
	xmas = 0
	for packet in pcap:
		try:
			if packet[TCP].flags == 0:
				null += 1
			if packet[TCP].flags == FIN:
				fin += 1
			if packet[TCP].flags == FIN | PSH | URG:
				xmas += 1
			if packet[TCP].dport == 80 and 'Authorization' in packet[TCP].load:
				print('found a password in cleartext')
		except IndexError:
			pass
		except AttributeError:
			pass
		if null != 0 and null % 1000 == 0:
			print('null')
	if fin > 20:
		print('fin')
	if xmas > 5:
		print('xmas')

def sniff_live(iface):
	print('sniffing')

args = sys.argv[1:]
try:
	if args[0] == '-h' or args[0] == '--help':
		print(USAGE, end='')
	elif args[0] == '-i':
		print('sniffing on ' + args[1] + ' ...')
		try:
			sniff(iface=args[1], prn=sniff_live)
		except socket.error:
			print('ERROR: interface not found')
			exit(1)
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
	try:
		sniff(iface='eth0', prn=sniff_live)
	except socket.error:
		print('ERROR: interface not found')
		exit(1)
