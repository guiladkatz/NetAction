# Use case 5.1.3 -- Early Congestion Updates

In this use case the programmable node computes several metrics that characterize the burstiness of a flow. Such metrics include:


## Prerequisite

For this DEMO, we needed a mechanism to artificially increase the occupation of the egress queues, to show the behavior of the use case at a time scale of seconds. To do this we added a "nanosleep" in the egrees queues that stalls the egress queues processing threads of 10 milliseconds.
This feature can be enabled at bmv2 compilation time, just for this use case, triggering the following commands in the directory containing the source code of the stateful bmv2 implementation:

    stateful-bmv2$ ./configure 'CXXFLAGS=-O0 -g -DSLOW_EGRESS_QUEUES'
    stateful-bmv2$ make


## Demo setup

First, create two networks connected by the bmv2 switch (we use here the same topology as in UC 1.0). The following bash script automatically sets up the namespaces and virtual ethernet interfaces:

	$ ./create_ns_4_veth.sh

The previous script will create three namespaces (lan, wan and switch) and 2 veth interface pairs, as UC1.0

In the Terminal in which the _create_ns_4_veth.sh_ script has been launched, run the following command to start the bmv2 switch with the two _veth1_ and _veth2_ interfaces:

	$ bash cmd

Finally, configure the mirroring session IDs with the bmv2 CLI:

	$ ip netns exec switch /path/to/simple_switch_CLI --thrift-port 50001 < cli_mirroring.txt

This is needed to configure the correct output ports for packets that must be cloned and sent back to the sender as an early congestion update.

## Test

In a new Terminal, access the _lan_ namespace:

	$ sudo ip netns exec lan bash

Open a capture in the lan namespace:

	$ sudo ip netns exec lan tcpdump -ni veth0

Next, in a new Terminal, again in lan namespace, execute bash script emulating traffic that slowly fills the egress queues. It contains 2 tcpreplay commands:
* the first slowly increases the egress queue occupation
* the second decreases the rate, resulting in a drecrease also in the egress occupation.

Run the script with:

	[lan]$ ./flood.sh


Now, at around 5 seconds after launching the script, we can see that the queue occupation overflows the threshold (set to 16). This results in packets being replayed back to the sender with the ECN flag set to "11", as the tcpdump capture should display.
Instead, when the egress queue returns back under threshold, the packet serving as updates are not anymore sent back to sender. 
