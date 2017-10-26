#!/usr/bin/env python2.7
from __future__ import print_function
import sys
from scapy.all import*

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

def main(args):
	# parse args and act accordingly
	try:
		if args[0] == '-h' or args[0] == '--help':
			print(USAGE, end='')
		elif args[0] == '-i':
			try:
				print('sniffing on ' + args[1] + ' ...')
				packets = sniff(iface=args[1], count=5000)
				analyze(packets)
			except IndexError:
				print(USAGE, end='')
		elif args[0] == '-r':
			try:
				print('analyzing ' + args[1] + ' ...')
				packets = rdpcap(args[1])
				analyze(packets)
			except IndexError:
				print(USAGE, end='')
				exit(1)
			except IOError:
				print('ERROR: file not found')
				exit(1)
		else:
			print(USAGE, end='')
			exit(1)
	# no args provided; sniff on eth0 by default
	except IndexError:
		print('sniffing on eth0')
#		while True:
		try:
			packets = sniff(iface='eth0', count=5000)
			analyze(packets)
		except socket.error:
			print('ERROR: interface not found')
			exit(1)
	except KeyboardInterrupt:
		print()
		exit(0)

# analyze static set of pre-captured packets
def analyze(pcap):
	num = 0
	null = 0
	fin = 0
	xmas = 0
	nikto = 0
	attacker = ''
	user = ''
	pswd = ''

	for packet in pcap:
		try:
			if packet[TCP].flags == 0:
				if packet[IP].src == attacker:
					null += 1
				else:
					attacker = packet[IP].src
					null = 1
				if null % 1000 == 0:
					num += 1
					alert('NULL', packet[IP].src, num)
			elif packet[TCP].flags == FIN:
				if packet[IP].src == attacker:
					fin += 1
				else:
					attacker = packet[IP].src
					fin = 1
				if fin % 1000 == 0:
					num += 1
					alert('FIN', attacker, num)
			elif packet[TCP].flags == FIN | PSH | URG:
				if packet[IP].src == attacker:
					xmas += 1
				else:
					attacker = packet[IP].src
					xmas = 1
				if xmas % 1000 == 0:
					num += 1
					alert('XMAS', attacker, num)
			if 'USER' in packet[TCP].load:
				user = packet[TCP].load[5:]
			if 'PASS' in packet[TCP].load:
				pswd = packet[TCP].load[5:]
				num += 1
				alert('password', packet[IP].src, num, user=user, pswd=pswd)
		except IndexError:
			pass
		except AttributeError:
			pass

def alert(incident, src, num, user='', pswd=''):
	if incident == 'XMAS' or incident == 'FIN' or incident == 'NULL' or \
	   incident == 'Nikto':
		msg = ('ALERT #' + str(num) + ': ' + incident + ' scan is detected '
               'from ' + src + ' (TCP)!')
	else:
		msg = ('ALERT #' + str(num) + ': Username and password sent '
               'in-the-clear from ' + src + ' (TCP) (' + user + ':' + pswd + \
		       ')!')
	print(msg)

main(sys.argv[1:])
