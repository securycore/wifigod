# WifiGod v1.0
Coded and Developed by Blackhole
Github: https://www.github.com/blacholesec

About the Tool:
 WifiGod is a tool coded and developing by Blackhole, it is written in the Python
 programming lanuage and is used to test network security.

Need to knows:
 .Monitor Interface is created for you:
   -When you enter you network interface in the options, always use one that is
    not already in monitor mode, use your main wireless interface (Ex: wlan0)
    this is because wifigod creates its' own wireless interface titled 'wifigod'
    when asked for a interface after the wifigod network interface is added
    (After first time of entering your main network interface) type 'wifigod'
    where it requests a network interface, the wifigod network interface is
    a prerequisite to the program, for it will not work without it.

 .Turn of main network interface for Network Jam and DeAuthentication:
    -It is recommended that you turn off your wireless interface (ex: wlan0)
     when using these options (DO NOT turn off Wifi). To temporarily disable
     the interface type: 'ifconfig wlan0 down' in which your network interface
     would replace 'wlan0'. The reason to doing this is, when the program sends
     the arbitrary packets to network it WILL preclude anyone on the network
     that YOU ARE CONNECTED TO from have a external wireless connection while
     the program runs. You are able to run this options fine without wifi.
     !HOWEVER! You must turn your wifi off AFTER you have executed the option
     for the program needs a working external connection to resolve device types
     for the DeAuthentication and 'Scan a Network for Devices' Options.

 .External Connection must be present for 'Scan a Network for Devices':
    -When Scanning a remote network for devices, it is imperative that you are
     able to connect to the internet. This is because the program looks up the
     found MAC addresses in a MAC Address Vendor Database.
