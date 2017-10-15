#!/usr/bin/env python3
import geocoder

ips = []
countries = {}
with open('JAR-16-20296A.csv') as jar:
	for line in jar:
		ip = {}
		info = line.replace('[.]', '.').split(',')
		try:
			if info[1] == 'IPV4ADDR':
				ip['addr'] = info[0]
				ip['location'] = geocoder.ip(info[0]).country
				if ip['location'] not in countries:
					countries[ip['location']] = 1
				else:
					countries[ip['location']] += 1
				ips.append(ip)
				print(ip['addr'] + ' located in ' + ip['location'])
		except IndexError:
			pass
for c in sorted(countries.keys()):
	print(c + ': ' + str(countries[c]))
