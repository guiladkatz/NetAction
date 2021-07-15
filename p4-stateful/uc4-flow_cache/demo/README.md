# Use Case 4 -- Flow Cache

This use case implements a scalable tunneling mechanism based on the differentiation of top talker flows (to be directly handled by the switch) and the reminders that are handled by specific network devices which contain very large connection tables.

## Network topology

      t1    t2     t3
        \    |    /
         DC_ROUTER
            | vxlan
            |
          SWITCH --------- OTR
            |
            | vlan-domain
           / \
          /   \
        S1     S2


t1,t2,t3 --> tenants, vxlans=100,200,300
DC ROUTER --> datacenter router. Encapsulates packets from tenants and decapsulate from switch IP=1.1.1.1
OTR --> receives |vlan|IP| packets, sends VXLAN encapsulated packets
S1,S2 --> bare-metal servers, receive VLAN --> send VLAN 

In this DEMO we the datacenter router and tenants are emulated with a Scapy python script that sends encapsulated packets emulating the tenants.

## Demo description

1. Packets received by the DC network port (i.e. VXLAN encapsulated packets) are simply decapsulated and sent to the proper BM server.
2. Packets received by the bare metal servers are processed by a stateful stage. The first packet of flows seen for the first time (state 0) is forwarded to the OTR. Subsequent packets are properly encapsulated in a VXLAN header according to thee information stored in the flow context (and learnt from OTR - see next numbered item)
3. Packets received from the OTR (i.e. packets encapsulated in the proper VXLAN tunnel and carrying the original BM server VLAN id in the reserved field of the VXLAN header) are forwarded to the stateful stage. If the state is 0 (i.e. the switch sill does not know how to route the packet into the VXLAN domain) the switch learns the association between the destination IP address and the VLAN id of the BM server by storing such info in the flow context (and by changing the state to 1).


## Demo setup

We start the setup by creating the network namespaces emulating the Datacenter, Bare-metal servers and OTR networks. The script to setup such networks creates 4 namespaces (datacenter, servers, otr and sswitch) with three veth pairs:

* **dc_sswitch---sswitch_dc** are the two interfaces (one attached to the datacenter namespace and the other to the switch namespace) creating the virtual eth link between the datacenter network and the stateful switch istance;
* **otr_sswitch---sswitch_otr**, similarly, create the link between the OTR instance and the stateful switch;
* **servers_sswitch---sswitch_server** create the link between the bare-metal server(s) and the stateful switch.

Run the script by triggering:

    $ sudo ./create_ns.sh

Run the stateful switch in the *sswitch* namespace:

    [sswitch]$ bash cmd

and load the bmv2 CLI command to install in the switch the stateless entry configuring the decapsulation and insertion of VLAN for datacenter flows directed to the server:

    [sswitch]$ /path/to/simple_switch_CLI --thift-port 50001 < table_cmds.txt

Now, in another terminal, run the server process in the servers namespace:

    $ sudo ip netns exec servers python3 server.py

This python script uses Scapy to: 
1. listen to incoming packets addressed to the server
2. swap addresses and ports to emulate a response to the tenant
3. sends back the packet to the stateful switch

Also the OTR needs a similar script to construct the packet needed from the stateful switch to learn the information to route the packets from the bare-metal servers to the VXLAN domain:
    
    $ sudo ip netns exec otr python3 otr.py

The *otr.py* python script uses Scapy to: 
1. listen to incoming VLAN packets
2. encapsulate the packet encoding the the VLAN id in the VXLAN *reserved2* header field 
3. sends back the packet to the stateful switch

We can now test the Flow Cache network fuction by sending traffic from the datacenter:

    [datacenter]$ python3 tenants.py

This python script send a VXLAN encapsulated packet to the bare-metal server. The packet incurs in the following processing:

1. The packet is received by the **stateful switch** that matches the stateless table entry configured before and:
    * decapsulates it 
    * sets the right VLAN id 
    * forwards it to the server
2. The **server** receives the packet and:
    * swap addresses and ports
    * sends back the packet to the stateful switch
3. The **stateful switch** processes the incoming packet in the stateful stage in **state 0**, so forwards it to the OTR
4. The **OTR** receives the packet and:
    * encapsulate the packet encoding the association info
    * sends it back to the stateful switch
5. The **stateful switch** receives the packet from the OTR and:
    * stores the destination IP address -- VLAN association in the appropriate flow registers
    * sets the state to 1 (LEARNT)
    * forwards the packet to the datacenter network

Now, to test the learning actually happened, rerun the *tenants.py* script in the datacenter namespace, that will send the same packet as before:

    [datacenter]$ python3 tenants.py

The steps 1 and 2 are the same as for the first packet, then the processing continues in this way:

3. The **stateful switch** processes the incoming packet in the stateful stage in **state 1** (LEARNT), so:
    * encapsulates the packet with the learnt VXLAN encapsulation
    * sends the encapsulated packet to the datacenter network