# Use case 1.2 - Dynamic NAT (Control plane)

In this use case the programmable node performs a “standard” dynamic NAT operation (e.g. the Linux’s MASQUERADE target).
In this version of the Dynamic NAT the free ports array must be updated by the Controller, to clean "expired" flows and consequently restore the free ports not being used anymore. In Use Case 1.3 instead, this is managed by the control plane.


## Demo setup

First, we have to create the networks emulating the WAN and the LAN. The following bash script automatically sets up the namespaces and virtual ethernet interfaces:

	$ ./create_ns_4_veth.sh

The previous script will create three namespaces (lan, wan and switch) and 2 veth interface pairs:
* *veth0* is assigned to the _lan_ namespace and will be attached to the LAN host behind the NAT. It is assigned with IP address 10.0.0.1;
* *veth3* is assigned to the _wan_ namespace and will be attached to the WAN host. It is assigned with IP address 160.80.10.1;
* *veth1* is the interface used by the bmv2 switch in the _switch_ namespace and it is linked with veth0 to the _lan_ namespace;
* *veth2* is the interface used by the bmv2 switch in the _switch_ namespace and it is linked with veth2 to the _wan_ namespace;

In the Terminal in which the _create_ns_4_veth.sh_ script has been launched, you should be *inside* the _switch_ namespace. In the _switch_ namespace run the following command to start the bmv2 switch with the two _veth1_ and _veth2_ interfaces:

	$ bash cmd

Since in this version of the NAT we assume that the Controller configures and keeps updated the list of free ports to be used, with this command we configure the Register Array configured in the bmv2 switch. 

To do so, we have to connect to the running switch via the bmv2 runtime CLI (*simple_switch_CLI*) and inject the CLI commands to configure the registers:

	$ /path/to/simple_switch_CLI --thrift-port 50001 < reg_cmd.txt

The *reg_cmd.txt* contains the following list of CLI commands:

	register_write IngressPipeImpl.natIPAddress 0 16843009

	register_write IngressPipeImpl.ports 0 10001
	register_write IngressPipeImpl.ports 1 10002
	register_write IngressPipeImpl.ports 2 10003
	register_write IngressPipeImpl.ports 3 10004
	register_write IngressPipeImpl.ports 4 10005
	register_write IngressPipeImpl.ports 5 10006
	register_write IngressPipeImpl.ports 6 10007
	register_write IngressPipeImpl.ports 7 10008
	register_write IngressPipeImpl.ports 8 10009
	register_write IngressPipeImpl.ports 9 10010

* The first command configures the IP address to be used as source IP address for NATted packets. The integer value *16843009* stands for *160.80.10.1* in dot-decimal notation, i.e. the address we used as NAT source IP address.
* The subsequent commands configure the first 10 elements of the register array containing the free NAT ports, in this case we choose a range from 10001 to 10010.


## Test

In a new Terminal, access the _lan_ namespace:

	$ sudo ip netns exec lan bash

In another trigger the same command to access the _wan_ namespace:

	$ sudo ip netns exec wan bash

Now, open a NetCat server in the WAN host:

	[wan]$ nc -lnkvp 2000

Then test a connection initialized from the LAN client:

	[lan]$ nc 160.80.10.1 2000

The connection is correctly established and we can see in the logs of the server that the first port used is 10001, i.e. the one we configured in the Register Array in position 0.

Now close the client netcat process and try to initiate another connection repeating the previous command. 

In the log you will see that for each new connection the source port will be incremented as configured in the free port array.
