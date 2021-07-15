# Use case 2.2 -- Flow Burstiness

In this use case the programmable node computes several metrics that characterize the burstiness of a flow. Such metrics include:

1. Number of bursts
2. Burst separation (ave, min, max)
3. Burst duration (ave, min, max)
4. Burst size in number of packets (ave, min, max)
5. Burst frequency (# of burst / T)


## Demo setup

First, create two networks connected by the bmv2 switch (we use here the same topology as in UC 1.0). The following bash script automatically sets up the namespaces and virtual ethernet interfaces:

	$ ./create_ns_4_veth.sh

The previous script will create three namespaces (lan, wan and switch) and 2 veth interface pairs, as UC1.0

In the Terminal in which the _create_ns_4_veth.sh_ script has been launched, run the following command to start the bmv2 switch with the two _veth1_ and _veth2_ interfaces:

	$ bash cmd

## Test

In a new Terminal, access the _switch_ namespace and run the following command to display every second the table dump with the bmv2 CLI:

	[switch]$ watch -n 1 "/path/to/simple_switch_CLI --thrift-port 50001 < dump.txt"

In a new Terminal, access the _lan_ namespace:

	$ sudo ip netns exec lan bash

Now, in lan namespace, execute bash script emulating bursty traffic. It is composed by a series of tcpreplay commands that replay packets at different speeds, in terms of packets per second, and with different durations.
Run the script with:

	[lan]$ ./burst_gen.sh

In the Terminal with the table dump, you will see the computed metrics changing in time.

Consider to play with the commands contained in the burst generation script to see how different flow bursts affect the metrics computation.