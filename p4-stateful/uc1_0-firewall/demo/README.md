# Use case 1.0 - Stateful Firewall

This use case implements the simplest stateful connection tracking mechanism: allow the forwarding of an application flow between the WAN and LAN only if initiated by the LAN. 

## Demo setup

First, we have to create the networks emulating the WAN and the LAN. The following bash script automatically sets up the namespaces and virtual ethernet interfaces:

	$ ./create_ns_4_veth.sh

The previous script will create three namespaces (lan, wan and switch) and 2 veth interface pairs:
- *veth0* is assigned to the _lan_ namespace and will be attached to the LAN host. It is assigned with IP address 10.0.0.1;
- *veth3* is assigned to the _wan_ namespace and will be attached to the WAN host. It is assigned with IP address 160.80.10.1;
- *veth1* is the interface used by the bmv2 switch in the _switch_ namespace and it is linked with veth0 to the _lan_ namespace;
- *veth2* is the interface used by the bmv2 switch in the _switch_ namespace and it is linked with veth2 to the _wan_ namespace;

In the Terminal in which the _create_ns_4_veth.sh_ script has been launched, you should be *inside* the _switch_ namespace. In the _switch_ namespace run the following command to start the bmv2 switch with the two _veth1_ and _veth2_ interfaces:

	$ /path/to/simple_switch -i 0@veth1 -i 1@veth2 --log-console --thrift-port 50001 ../stateful_firewall_IR_hacked.json

The bmv2 switch is now running with the LOG output in the console in which the script has been run.

NOTE: the previous command is contained in the _cmd_ file and can be executed directly by running:

	$ bash cmd


## Test

In a new Terminal, access the _lan_ namespace:

	$ sudo ip netns exec lan bash

In another trigger the same command to access the _wan_ namespace:

	$ sudo ip netns exec wan bash

Now, open a NetCat server in the WAN host:

	[wan]$ nc -lnkvp 2000

Then test a connection initialized from the LAN client:

	[lan]$ nc 160.80.10.1 2000

The connection is correctly established, as expected, since it is initiated from the lan and since it's a TCP connection, also the packets from the server in WAN are correctly forwarded to the client in LAN.


Now, close client and server netcat processes and try to initate a connection from WAN to LAN:

	[lan]$ nc -lnkvp 2000
	[wan]$ nc 10.0.0.1 2000

In this case, the first packet is dropped and the connection cannot be established as expected.
