COMP 116 Lab 3 (Packet Sleuth) -- Adon Shapiro
==============================================

set1.pcap
---------
1. 5748 packets
2. FTP
3. FTP does not support encrypted connections. This means that all files and
	data sent with the protocol (including user credentials) could easily
	be read by anyone intercepting traffic.
4. SFTP, FTPS, HTTPS, SCP are all secure, encrypted protocols for file transfer
5. 192.168.1.8
6. username: tom, password: WinnonaWasBehindEquifaxHack
7. 5 files were transferred
8. CyDLRVHUcAATK7n.jpg, DGBCHRSUwAAmAcC.jpg, geer.source.27iv17.txt,
	IMG\_0705.JPG, IMG\_0762.JPG
9. done

set2.pcap
---------
10. 76804 packets
11. I found five username-password pairs, but they are all the same pair. So
	only one unique pair.
12. user: b4ckd00r@protonmail.ch, pass: Apartamento123! used HTTP to connect to
	thiscrush.com at 104.245.88.151, port 80
13. Seems legit. There's a valid http response (redirect to php script), and
	traffic continues afterward.
14. All IPs and domains:
	* 172.217.5.202 -- googleapis.l.google.com
	* 172.217.4.170 -- googleapis.l.google.com
	* 216.115.100.124 -- flickr-panda-police.a00.yahoodns.net
	* 216.115.100.123 -- flickr-panda-police.a00.yahoodns.net
	* 54.171.35.161 -- nginx-prod-eu-west-1-ext-a-910855309.eu-west-1.elb.amazonaws.co
	* 216.58.216.42 -- googleapis.l.google.com
	* 52.4.16.139 -- display.provenpixel.com
	* 52.84.243.175 -- vast.streamrail.net
	* 52.84.243.226 -- vast.streamrail.net
	* 192.33.14.30 -- b.gtld-servers.NET
	* 23.61.194.8 -- a1089.d.akamai.net
	* 17.248.129.176 -- p16-caldav.fe.apple-dns.net
	* 52.84.243.225 -- vast.streamrail.net
	* 17.248.129.175 -- p16-caldav.fe.apple-dns.net
	* 172.217.11.74 -- googleapis.l.google.com
	* 52.84.243.223 -- vast.streamrail.net
	* 17.248.129.173 -- p16-caldav.fe.apple-dns.net
	* 17.167.194.149 -- gs-loc.ls-apple.com.akadns.net
	* 192.26.92.30 -- c.gtld-servers.NET
	* 52.49.50.67 -- nginx-prod-eu-west-1-ext-a-910855309.eu-west-1.elb.amazonaws.co
	* 54.171.205.114 -- nginx-prod-eu-west-1-ext-a-910855309.eu-west-1.elb.amazonaws.co
	* 31.13.71.14 -- video-lga3-1.xx.fbcdn.net
	* 216.58.216.35 -- beacons-handoff.gcp.gvt2.com
	* 34.249.164.51 -- vid-io.springserve.com
	* 52.84.243.115 -- vast.streamrail.net
	* 192.5.6.30 -- a.gtld-servers.NET
	* 172.217.11.170 -- googleapis.l.google.com
	* 54.82.67.239 -- central.github.com
	* 52.208.19.123 -- vid-io.springserve.com
	* 52.84.243.114 -- vast.streamrail.net
	* 173.8.102.75 -- rumkin.com
	* 50.93.247.155 -- aad-msp.crashplan.com
	* 34.249.135.161 -- vid-io.springserve.com
	* 17.167.192.128 -- gs-loc.ls-apple.com.akadns.net
	* 52.84.244.193 -- d3uelno863zh3a.cloudfront.net
	* 52.17.241.2 -- vid-io.springserve.com
	* 74.125.28.189 -- browserchannel-docs.l.google.com
	* 52.4.187.213 -- display.provenpixel.com
	* 208.71.45.11 -- ds2-global.l7.search.ystg1.b.yahoo.com
	* 208.71.44.31 -- flickr-panda-police.a00.yahoodns.net
	* 217.212.252.105 -- a1843.g.akamai.net
	* 208.71.44.30 -- flickr-panda-police.a00.yahoodns.net
	* 172.217.4.142 -- ytimg.l.google.com
	* 216.58.219.10 -- googleapis.l.google.com
	* 52.84.243.98 -- vast.streamrail.net
	* 23.198.161.133 -- e2842.e9.akamaiedge.net
	* 172.217.4.138 -- googleapis.l.google.com
	* 96.114.157.78 -- imap.g.comcast.net
	* 17.248.129.201 -- p16-caldav.fe.apple-dns.net
	* 52.214.80.173 -- nginx-prod-eu-west-1-ext-a-910855309.eu-west-1.elb.amazonaws.co
	* 216.58.216.14 -- www3.l.google.com
	* 17.248.129.200 -- p16-caldav.fe.apple-dns.net
	* 216.58.216.13 -- accounts.google.com
	* 17.248.129.147 -- p16-caldav.fe.apple-dns.net
	* 34.253.107.46 -- vid-io.springserve.com
	* 17.253.23.203 -- mesu.g.aaplimg.com
	* 17.248.129.146 -- p16-caldav.fe.apple-dns.net
	* 17.253.23.201 -- mesu.g.aaplimg.com
	* 217.212.252.95 -- a1843.g.akamai.net
	* 54.154.184.149 -- nginx-prod-eu-west-1-ext-a-910855309.eu-west-1.elb.amazonaws.co
	* 172.217.4.131 -- gstaticadssl.l.google.com
	* 54.171.189.249 -- nginx-prod-eu-west-1-ext-a-910855309.eu-west-1.elb.amazonaws.co
	* 34.253.79.236 -- vid-io.springserve.com
	* 192.30.255.113 -- github.com
	* 192.30.255.112 -- github.com
	* 108.177.98.188 -- mobile-gtalk.l.google.com
	* 216.58.216.4 -- www.google.com
	* 165.227.0.37 -- vtfbctf.com
	* 127.0.0.1 -- localhost
	* 63.251.109.84 -- cacp-hlb.dvgtm.akadns.net
	* 69.36.145.33 -- pdns2.cscdns.net
	* 23.61.194.19 -- a1089.d.akamai.net
	* 54.154.101.248 -- nginx-prod-eu-west-1-ext-a-910855309.eu-west-1.elb.amazonaws.co
	* 17.248.129.238 -- p16-caldav.fe.apple-dns.net
	* 2.20.86.213 -- e13136.g.akamaiedge.NET
	* 52.5.245.109 -- display.provenpixel.com
	* 52.16.17.68 -- vid-io.springserve.com
	* 192.31.80.30 -- d.gtld-servers.NET
	* 52.0.149.162 -- display.provenpixel.com
	* 54.154.31.199 -- nginx-prod-eu-west-1-ext-a-910855309.eu-west-1.elb.amazonaws.co
	* 52.209.217.101 -- vid-io.springserve.com
	* 52.84.243.131 -- vast.streamrail.net
	* 192.12.94.30 -- e.gtld-servers.NET

set3.pcap
---------
15. 81266 packets
16. just one
17. user: lb@greaterhealth4all.com, pass: @Cts238truth used IMAP to connect to
	64.68.200.59, port 143
18. It seems legit. There are valid responses from the server and some
	interactions with an IMAP mailbox follow the authentication.

set4.pcap
---------
19. Three username-password pairs
20. Each pair used HTTP to connect to www.cs.tufts.edu at 130.64.23.35, port 80
21. Valid/Invalid Pairs
	* user: DeannaBessy, pass: WillBeComingBackToRecruit is invalid
	* user: AnneOursler, pass: IsAnExpertOnInternetOfThings is invalid
	* user: GoGetMeABeer, DafuqIsThisShit? is invalid

General Questions
-----------------
22. I used ettercap on the pcaps and piped the output through grep, searching
	for strings containing "PASS"
23. I followed the TCP stream in wireshark and guessed based on the responses
	from the server.
24. Don't enter sensitive information over insecure, unencrypted protocols.
