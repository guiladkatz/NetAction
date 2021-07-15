# Use case 2.1 -- Flow Duration

In this use case the programmable node computes the flow duration, i.e. the difference between the timestamp of the first and the last packet of a flow.

## Demo setup

First, create two networks connected by the bmv2 switch (we use here the same topology as in UC 1.0). The following bash script automatically sets up the namespaces and virtual ethernet interfaces:

	$ ./create_ns_4_veth.sh

The previous script will create three namespaces (lan, wan and switch) and 2 veth interface pairs:
* *veth0* is assigned to the _lan_ namespace and will be attached to the LAN host behind the NAT. It is assigned with IP address 10.0.0.1;
* *veth3* is assigned to the _wan_ namespace and will be attached to the WAN host. It is assigned with IP address 192.168.0.1;
* *veth1* is the interface used by the bmv2 switch in the _switch_ namespace and it is linked with veth0 to the _lan_ namespace;
* *veth2* is the interface used by the bmv2 switch in the _switch_ namespace and it is linked with veth2 to the _wan_ namespace;

In the Terminal in which the _create_ns_4_veth.sh_ script has been launched, you should be *inside* the _switch_ namespace. In the _switch_ namespace run the following command to start the bmv2 switch with the two _veth1_ and _veth2_ interfaces:

	$ bash cmd

## Test

In a new Terminal, access the _switch_ namespace and run the following command to display every second the table dump with the bmv2 CLI:

	[switch]$ watch -n 1 "/path/to/simple_switch_CLI --thrift-port 50001 < dump.txt"

In a new Terminal, access the _lan_ namespace:

	$ sudo ip netns exec lan bash

Then replay a packet at 1pps rate with the following command:

	$ tcpreplay -i veth0 -p 1 ../../tools/simple_ip4_tcp.pcap

In the Terminal with the table dump, you will see that the register measuring the flow duration is increased at each packetl, representing the difference between the timestamp of the last and first packets.