# The names of the interfaces will probably be different once you bring them up in Mininet.
# After you bring up the topology in Mininet, check the name and modify accordingly.
# e.g., s1-eth2 is the name of the interface on switch 1, connecting it to switch 2. But, the NAME of the interface may not be as I wrote!
# Therefore, pay attention to the ROLE of the interface, not it's name.
# NOTE: Some of the address listed down here are automatically configured by mininet when starting the environment (e.g., 10.0.1.1)
# NOTE 2: The assumption is that h1 and h3 are the only ones who will try to PING each other. h2 is the controller.

# Configure Switch 1 underlay IP addresses
s1 ifconfig s1-eth2 192.168.0.12 netmask 255.255.255.0 up # At s1, assign the address 192.168.0.12 to the s1 <-> s2 interface.
s1 ifconfig s1-eth3 192.168.0.13 netmask 255.255.255.0 up # At s1, assign the address 192.168.0.13 to the s1 <-> s3 interface.

# Configure Switch 2 underlay IP addresses
s2 ifconfig s2-eth1 192.168.0.21 netmask 255.255.255.0 up # At s2, assign the address 192.168.0.21 to the s2 <-> s1 interface.
s2 ifconfig s2-eth2 192.168.0.22 netmask 255.255.255.0 up # At s2, assign the address 192.168.0.22 to the s2 <-> Controller (h2) interface.
s2 ifconfig s2-eth3 192.168.0.23 netmask 255.255.255.0 up # At s2, assign the address 192.168.0.23 to the s2 <-> s3 interface.

# Configure Switch 2 underlay IP addresses
s3 ifconfig s3-eth1 192.168.0.31 netmask 255.255.255.0 up # At s3, assign the address 192.168.0.31 to the s3 <-> s1 interface.
s3 ifconfig s3-eth2 192.168.0.32 netmask 255.255.255.0 up # At s3, assign the address 192.168.0.32 to the s3 <-> s2 interface.

# Configure the underlay IP address of the Controller
h2 ifconfig h2-eth0 192.168.0.100 netmask 255.255.255.0 up
# Change the MAC Address of the controller <-> Switch interface (for comfort reasons..)
h2 ifconfig h2-eth0 hw ether 00:00:00:aa:aa:02

# Add static routes to the hosts routing tables (Needed for the PING command to start)
h1 ip route add 10.0.3.0/24 dev h1-eth0 # in h1, add static route to h2's network (e.g., If the IP address of h3 was 10.0.3.3, its network is 10.0.3.0, and to reach it you need to leave from interface h1-eth0)
h3 ip route add 10.0.1.0/24 dev h2-eth0 # in h3, add static route to h1's network

# Configure static ARP table entries, so when issuing commands (e.g., PING) to those IP addresses, no ARP request will be issued
# At the time, I didn't handle ARP request in the P4 code of the switches, so I wanted to avoid dealing with them, so this was the solution I came up with.
# Later on, I added a table in P4 to handle ARP requests

h1 arp -s 10.0.3.3 00:00:00:00:03:03 # In h1, add static ARP table entry to the host with IP address 10.0.3.3 and MAC address 00:00:00:00:03:03
h3 arp -s 10.0.1.1 00:00:00:00:01:01 # In h3, add static ARP table entry to the host with IP address 10.0.1.1 and MAC address 00:00:00:00:01:01

xterm h2 # Start the terminal on h2 (i.e., The controller) to be ready to start te controller program
