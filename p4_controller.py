#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse, grpc, os, sys, json
import time
from time import sleep
import thread
import Queue
import socket
import struct
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import *



# set our lib path
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '../../../utils/'))

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

# And then we import
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


def insert_table_entry_t_vxlan_term(p4info_helper, sw, dst_eth_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress.upstream.t_vxlan_term",
        match_fields = {
            "hdr.inner_ethernet.dstAddr": dst_eth_addr
        },
        action_name = "basic_tutorial_ingress.upstream.vxlan_decap",
        action_params = {
        })
    sw.WriteTableEntry(table_entry)
    print "Installed t_vxlan_term entry via P4Runtime."

def insert_table_entry_t_forward_l2(p4info_helper, sw, dst_eth_addr, port=None):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress.upstream.t_forward_l2",
        match_fields = {
            "hdr.inner_ethernet.dstAddr": dst_eth_addr
        },
        action_name = "basic_tutorial_ingress.upstream.forward",
        action_params = {
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print "Installed t_forward_l2 entry via P4Runtime."

def insert_table_entry_t_forward_underlay(p4info_helper, sw, ip_dstAddr, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress.upstream.t_forward_underlay",
        match_fields = {
            "hdr.ipv4.dstAddr": ip_dstAddr
        },
        action_name = "basic_tutorial_ingress.upstream.forward_underlay",
        action_params = {
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print "Installed t_forward_l2 entry via P4Runtime."

def insert_table_entry_t_vxlan_segment(p4info_helper,downstream_id, sw, ingress_port, vni):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".t_vxlan_segment",
        match_fields = {
            "standard_metadata.ingress_port": ingress_port
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".set_vni",
        action_params = {
            "vni": vni
        })
    sw.WriteTableEntry(table_entry)
    print "Installed t_vxlan_segment_set_vni entry via P4Runtime."

def insert_table_entry_flow_cache(p4info_helper,downstream_id, sw, dst_ip_addr, outter_ip, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".set_outer_dst_ip",
        action_params = {
            "dst_ip": outter_ip,
            "port"  : port
        })
    sw.WriteTableEntry(table_entry)
    print "Installed flow_cache entry via P4Runtime."

def insert_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.WriteTableEntry(table_entry)
    print "Installed flow_cache drop entry via P4Runtime."

def insert_table_entry_t_vtep(p4info_helper,downstream_id, sw, src_eth_addr, vtep_ip):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".t_vtep",
        match_fields = {
            "hdr.ethernet.srcAddr": src_eth_addr
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".set_vtep_ip",
        action_params = {
            "vtep_ip": vtep_ip
        })
    sw.WriteTableEntry(table_entry)
    print "Installed t_vtep entry via P4Runtime."

def insert_table_entry_t_controller(p4info_helper,downstream_id, sw, key_port, ip_dstAddr, param_port):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".t_controller",
        match_fields = {
            "standard_metadata.egress_spec": key_port
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".set_controller_ip_and_port",
        action_params = {
            "dst_ip"      : ip_dstAddr,
            "port"        : param_port
        })
    sw.WriteTableEntry(table_entry)
    print "Installed t_controller entry via P4Runtime."

def insert_table_entry_t_send_frame(p4info_helper, sw, dst_ip_addr, smac, dmac):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_egress.downstream.t_send_frame",
        match_fields = {
            "hdr.ipv4.dstAddr": dst_ip_addr
        },
        action_name = "basic_tutorial_egress.downstream.rewrite_macs",
        action_params = {
            "smac": smac,
            "dmac": dmac
        })
    sw.WriteTableEntry(table_entry)
    print "Installed t_send_frame entry via P4Runtime."

def delete_table_entry_flow_cache(p4info_helper,downstream_id, sw, dst_ip_addr, outter_ip, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".set_outer_dst_ip",
        action_params = {
            "dst_ip": outter_ip,
            "port"  : port
        })
    sw.DeleteTableEntry(table_entry)
    print "Deleted flow_cache entry via P4Runtime."

def delete_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.DeleteTableEntry(table_entry)
    print "Deleted flow_cache entry via P4Runtime."

def get_k_lfu_rules(p4info_helper, sw, table_name):
    table_id = p4info_helper.get_tables_id(table_name)
    all_rules = []
    for response in sw.ReadTableEntries(table_id=table_id):
        for entity in response.entities:
            entry = entity.table_entry
            full_table_name = p4info_helper.get_tables_name(entry.table_id)
            table_name = full_table_name.split(".")
            if table_name[2] == "lfu":
                param_port = 0
                param_ip = 0
                downstream = table_name[1]
                name = table_name[2]
                key_ip = socket.inet_ntoa(p4info_helper.get_match_field_value(entry.match[0])[0])
                action = entry.action.action
                action_name = p4info_helper.get_actions_name(action.action_id)
                for p in action.params:
                    param_name = p4info_helper.get_action_param_name(action_name, p.param_id)
                    if(param_name == "dst_ip"):
                        param_ip = socket.inet_ntoa(p.value)
                    else:
                        param_port = struct.unpack('>H', p.value)[0]
                all_rules.append([downstream,name,key_ip,param_ip,param_port,0])
    return all_rules


    """
    rules = []
    request = "Give me the k LFU Rules"
    src_mac ='00:00:00:00:01:05'
    dst_mac ='00:00:00:00:01:05'
    controller_ip = "192.168.0.100"
    switch_ip = '192.168.0.5'
    src_port = 50100
    dst_port = 1234
    send_pkt = Ether(src=src_mac, dst=dst_mac)
    send_pkt = send_pkt / IP(dst=switch_ip) / TCP(dport=dst_port, sport=src_port)
    send_pkt = send_pkt / request
    sendp(send_pkt, iface="h5-eth0", verbose=False)

    flag = False
    while(flag == False):
        if not q.empty():
            rec_pkt = q.get()
            if(rec_pkt.haslayer(UDP)):
                if(rec_pkt.getlayer(UDP).dport == 50100):
                    flag = True
                    print("Received packet in get k lfu rules is:")
                    pkt_rules = rec_pkt.payload.payload.payload
                    print("The type of the payload is:")
                    print(type(pkt_rules))
                    print(pkt_rules)
                    if(len(pkt_rules) > 0):
                        pkt_rules = str(pkt_rules)
                        rules = pkt_rules.split(";")
                    print("The rules are:")
                    print(rules)
                    table_rules[sw.name] = rules
                else:
                    q.put(rec_pkt)
            else:
                 q.put(rec_pkt)
    """


def readTableRules(p4info_helper, sw, table_name):  
    #Reads the table entries from all tables on the switch.
    #TODO - Give the table id of the cache to the ReadTableEntries() function to read only from the cache
    table_id = p4info_helper.get_tables_id(table_name)
    rules = []
    for response in sw.ReadTableEntries(table_id=table_id):
        for entity in response.entities:
            entry = entity.table_entry
            full_table_name = p4info_helper.get_tables_name(entry.table_id)
            table_name = full_table_name.split(".")
            if table_name[2] == "flow_cache":
                param_port = 0
                param_ip = 0
                downstream = table_name[1]
                name = table_name[2]
                key_ip = socket.inet_ntoa(p4info_helper.get_match_field_value(entry.match[0])[0])
                action = entry.action.action
                action_name = p4info_helper.get_actions_name(action.action_id)
                for p in action.params:
                    param_name = p4info_helper.get_action_param_name(action_name, p.param_id)
                    if(param_name == "dst_ip"):
                        param_ip = socket.inet_ntoa(p.value)
                    else:
                        param_port = struct.unpack('>H', p.value)[0]
                rules.append([downstream,name,key_ip,param_ip,param_port,0])
    #Reads the counters entries from all table entries on the cache.
    for rule in rules:
        table_name = "basic_tutorial_ingress." + rule[0] + ".flow_cache"
        dst_ip_addr = rule[2]
        table_entry = p4info_helper.buildTableEntry(
        table_name = table_name,
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        })
        for response in sw.ReadDirectCounter(table_entry = table_entry, table_id = p4info_helper.get_tables_id(table_name)):
            for entity in response.entities:
                direct_counter_entry = entity.direct_counter_entry
                #print "The switch is: %s: %d packets" % (sw.name, direct_counter_entry.data.packet_count)
            rule[5] = int("%d"%( direct_counter_entry.data.packet_count))
    table_rules[sw.name] = rules

def printGrpcError(e):
    print "gRPC Error: ", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print "[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)


def sniff_and_enqueue():
    while True:
        packets = sniff(iface="h5-eth0",filter="dst host 192.168.0.100",count=1)
        q.put(packets[0])

def flow_count(src,dst):
    flow_count = 0
    if (src,dst) in flow_counter:
        flow_counter[(src,dst)] += 1
        flow_count = flow_counter[(src,dst)]
    else:
        if (dst,src) in flow_counter:
            flow_counter[(dst,src)] += 1
            flow_count = flow_counter[(dst,src)]
        else:
            flow_counter[(src,dst)] = 0

    return flow_count

def takeCounter(elem):
    return elem[5]

def takeBool(elem):
    return elem[1]

def ip_to_insert(oracle, pkt_src_mac, pkt_dst_mac,s1,s2):
    ip = "0.0.0.0"
    if(oracle[pkt_dst_mac][0] != oracle[pkt_src_mac][0]): #If the sender and receiver are not on the same switch
        if(oracle[pkt_dst_mac][0] == s2):
            ip = "192.168.0.2"
        if(oracle[pkt_dst_mac][0] == s1):
            ip = "192.168.0.1"
    return ip

def resolve_outter_ip(oracle, pkt_src_mac, pkt_dst_mac,s1,s2):
    outter_ip = "0.0.0.0"
    if(oracle[pkt_dst_mac][0] == s2):
        outter_ip = "192.168.0.2"
    if(oracle[pkt_dst_mac][0] == s1):
        outter_ip = "192.168.0.1"
    return outter_ip

def resolve_egress_port(oracle,pkt_src_mac,pkt_dst_mac,s1,s2):
    egress_port =  oracle[pkt_dst_mac][2]
    if(oracle[pkt_dst_mac][0] != oracle[pkt_src_mac][0]): #If the sender and receiver are not on the same switch
        if(oracle[pkt_dst_mac][0] == s2):
            egress_port = "\000\004"
        if(oracle[pkt_dst_mac][0] == s1):
            egress_port = "\000\003"
    return egress_port

def plot_statistics(p4info_helper,sw1):
    sleep(600)
    readTableRules(p4info_helper,sw1)
    rules = table_rules[sw1.name]
    flow_list = []
    rule_hits_list = []
    cache_time_list = []
    for rule in rules:
        global_history[rule[2]][0] +=  rule[5]
        global_history[rule[2]][4] +=  time.time() - global_history[rule[2]][3]


    new_global_history_hit_sort = sorted(global_history.items(), key=lambda x: x[1][0], reverse=True)
    print("After sorting by hit")
    print(new_global_history_hit_sort)
    for elem in new_global_history_hit_sort:
        flow_list.append(elem[0])
        rule_hits_list.append(elem[1][0])

    new_global_history_time_in_cache_sort = sorted(global_history.items(), key=lambda x: x[1][4], reverse=True)
    for elem in new_global_history_time_in_cache_sort:
        cache_time_list.append(elem[1][4])
    print("After sorting by time in cache")
    print(new_global_history_time_in_cache_sort)
    flow_index = list(range(len(cache_time_list)))
    print(flow_index)
    title1 ="Cache Performance"

    fig1, (ax1,ax2) = plt.subplots(1,2)
    fig1.suptitle(title1)

    ax1.plot(flow_index,rule_hits_list)
    ax1.set_xlabel('Flow Number')
    ax1.set_ylabel('Number of Hits')
    ax1.set_title('Cache Hits')

    ax2.plot(flow_index,cache_time_list)
    ax2.set_xlabel('Flow Number')
    ax2.set_ylabel('Time in Cache')
    ax2.set_title('Time in Cache')

    fig1.show()
    plt.show()
    
def get_cache_size():
    rules_in_cache = 0
    for rule in global_history.values():
        if rule[1] == True:
            rules_in_cache+=1
    return rules_in_cache

def cache_handler(p4info_helper,sw1,pkt_dst_ip):

    if pkt_dst_ip not in global_history:
        global_history[pkt_dst_ip] = [1,False,time.time(),0,0] #[Count, Is_in_cache, Arrival_time, Cache_insertion_time, Overall_time_in_cache]  
        recent_history[pkt_dst_ip] = 1
    else:
        if pkt_dst_ip not in recent_history:
            recent_history[pkt_dst_ip] = 1
        else:
            recent_history[pkt_dst_ip] += 1
            if recent_history[pkt_dst_ip] >= threshold:
                rules_in_cache = get_cache_size()
                if(rules_in_cache < cache_size):
                    insert_table_entry_flow_cache_drop(p4info_helper,"downstream", sw1, str(pkt_dst_ip))
                    global_history[pkt_dst_ip][1] = True
                    global_history[pkt_dst_ip][3] = time.time()
                else:
                    rules = get_k_lfu_rules(p4info_helper,sw1,"basic_tutorial_ingress.downstream.lfu")
                    #insert_table_entry_flow_cache_drop(p4info_helper,"downstream", sw1, str(pkt_dst_ip))
                    #readTableRules(p4info_helper,sw1)
                    #rules = table_rules[sw1.name]
                    #rules.sort(key=takeCounter)
                    print(rules)
                    lfu = rules[0]
                    global_history[lfu[2]][0] += lfu[5]
                    global_history[lfu[2]][1] = False
                    global_history[lfu[2]][4] += time.time() - global_history[lfu[2]][3]
                    del recent_history[lfu[2]]
                    delete_table_entry_flow_cache_drop(p4info_helper,"downstream", sw1, lfu[2])                   
                    insert_table_entry_flow_cache_drop(p4info_helper,"downstream", sw1, str(pkt_dst_ip))
                    global_history[pkt_dst_ip][1] = True
                    global_history[pkt_dst_ip][3] = time.time()


def main(p4info_file_path, bmv2_file_path, my_topology):
    # Instantiate a P4Runtime helper from the p4info file
    # - then need to read from the file compile from P4 Program, which call .p4info
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    try:
        # Create 3 P4Runtime client instances - 1 for each switch. All the communication between the controller and the switches will be made throught this instances.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='192.168.0.11:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='192.168.0.12:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='192.168.0.13:50053',
            device_id=1,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # MasterArbitrationUpdate() command sends three parameters, from which the P4Runtime server (i.e., The switch) decides who is the master.
        # Only the master can perform write operations (e.g., Rule insertion, Counters initialization). Any client can perform read operations (e.g., Read rules or counters)
        # This command is required by P4Runtime before performing any other write operation
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 Pipeline into the switches, as is defined by the P4Info file. This file defines the names and IDs of the P4 objects that needs to be used by 
        # the client (Controller) and the server (Switch). The P4Info file is created by the P4C compiler at compilation time.

        # Both MasterArbitrationUpdate() and SetForwardingPipelineConfig() are defined in switch.py under utils directory.
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForardingPipelineConfig on s1"

        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForardingPipelineConfig on s2"

        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForardingPipelineConfig on s3"

        count=0
        h1 = "00:00:00:00:01:01"
        h3 = "00:00:00:00:03:03"
        oracle  =  {"00:00:00:00:01:01":[s1,"10.0.1.1","\000\001",0x100000],#(MAC: [Switch,IP,Port,VNI])
                    "00:00:00:00:03:03":[s3,"10.0.3.3","\000\003",0x100000]
                    }
        table_rules[s1.name] = []
        table_rules[s2.name] = []


        ############################### Insert flow rules for Switch 1 ###############################

        ################# Ingress Upstream Rules #################

        # In Switch 1, if the host with MAC address 00:00:00:00:01:01 is connected to it, then decapsulate the packet
        insert_table_entry_t_vxlan_term(p4info_helper, sw=s1, dst_eth_addr="00:00:00:00:01:01")
        # In Switch 1, if the host with MAC address 00:00:00:00:01:01 is connected to it, then forward on port 1
        insert_table_entry_t_forward_l2(p4info_helper, sw=s1, dst_eth_addr="00:00:00:00:01:01", port="\000\001") 

        # In Switch 1, if the destination IP address of the outter IPv4 header is one of those three,
        # then the packet is not destined to a host in this switch, and shouldn't be decapsulated, simply forwarded to the specified port
        # It will have more importance in switch 2, because it is directly connected to the controller.
        insert_table_entry_t_forward_underlay(p4info_helper, sw=s1, ip_dstAddr="192.168.0.100", port="\000\002") # the number may change, bu the port is s1 <-> s2 port
        insert_table_entry_t_forward_underlay(p4info_helper, sw=s1, ip_dstAddr="192.168.0.21", port="\000\002")
        insert_table_entry_t_forward_underlay(p4info_helper, sw=s1, ip_dstAddr="192.168.0.31", port="\000\003") # the number may change, bu the port is s1 <-> s3 port

        ################# Ingress Downstream Rules #################

        # In Switch 1 If the packet missed the cache, match against the TEMP_PORT (10 (0xa) in this case) which will always match, assign the IP of the controller to the packet, and send it to the controller through it's port (3 in this case)
        # A better approach should be taken!
        insert_table_entry_t_controller(p4info_helper,"downstream", sw=s1, key_port="\000\00a", ip_dstAddr="192.168.0.100", param_port="\000\003")
        
        # In Switch 1, match against the MAC address 00:00:00:00:01:01 and assign the address of the Vtep, which in this case should be 192.168.0.13
        # The reason is that in this particular topology, Host 1 will try to send packets only to Host 3 (because Host 2 is the controller)
        # and thus the Vtep IP address is the address of s1's interface to s3.
        insert_table_entry_t_vtep(p4info_helper,"downstream",sw=s1, src_eth_addr="00:00:00:00:01:01", vtep_ip="192.168.0.13")

        # In Switch 1, if the packet came from the device connected to port 1 (Host 1 in this case), then assign it the VNI of 0x100000 (The value was chosen arbitrarly)
        insert_table_entry_t_vxlan_segment(p4info_helper,"downstream", sw=s1, ingress_port="\000\001", vni=0x100000)

        # In Switch 1, If a packet's destination IP address is 10.0.3.3 (Host 3's IP address), then set the outter destination IP address to be the address of Switch 3's interface with Switch 1
        # and assign the egress port accordingly (Switch 3 is connected to port 3 in this case)
        # NOTE: If you want to test the behavior of the cache and the controller, comment this line and see if the controller inserts the rule to the cache! (This is really the point of the project right?)
        insert_table_entry_flow_cache(p4info_helper,"downstream", sw=s1, dst_ip_addr="10.0.3.3", outter_ip="192.168.0.31", port="\000\003")






        ############################### Insert flow rules for Switch 2 ###############################

        ################# Ingress Upstream Rules #################

        # The only host connected to Switch 2 is h2 which is the controller. We don't want to decapsulate the packets before forwarding them to the controller
        # So basically, in the upstream, Switch 2 will only forward packets. 

        insert_table_entry_t_forward_underlay(p4info_helper, sw=s2, ip_dstAddr="192.168.0.100", port="\000\002") # the number may change, bu the port is s2 <-> h2 port (controller)
        insert_table_entry_t_forward_underlay(p4info_helper, sw=s2, ip_dstAddr="192.168.0.12", port="\000\001") # the number may change, bu the port is s2 <-> s1 port
        insert_table_entry_t_forward_underlay(p4info_helper, sw=s2, ip_dstAddr="192.168.0.32", port="\000\003") # the number may change, bu the port is s2 <-> s3 port

        # In this topology, switch 2 doesn't need downstream rules, since all the packets entering the switch are either from the controller, or from other switches.



        ############################### Insert flow rules for Switch 3 ###############################

        ################# Ingress Upstream Rules #################

        insert_table_entry_t_vxlan_term(p4info_helper, sw=s3, dst_eth_addr="00:00:00:00:03:03")
        insert_table_entry_t_forward_l2(p4info_helper, sw=s3, dst_eth_addr="00:00:00:00:03:03", port="\000\003") 

        insert_table_entry_t_forward_underlay(p4info_helper, sw=s3, ip_dstAddr="192.168.0.100", port="\000\002") # the number may change, bu the port is s3 <-> s2 port
        insert_table_entry_t_forward_underlay(p4info_helper, sw=s3, ip_dstAddr="192.168.0.13", port="\000\001") # the number may change, bu the port is s3 <-> s1 port
        insert_table_entry_t_forward_underlay(p4info_helper, sw=s3, ip_dstAddr="192.168.0.23", port="\000\002") # the number may change, bu the port is s3 <-> s2 port

        ################# Ingress Downstream Rules #################

        insert_table_entry_t_controller(p4info_helper,"downstream", sw=s3, key_port="\000\00a", ip_dstAddr="192.168.0.100", param_port="\000\002") # Again, the number 2 may change!
        insert_table_entry_t_vtep(p4info_helper,"downstream",sw=s3, src_eth_addr="00:00:00:00:03:03", vtep_ip="192.168.0.31")
        insert_table_entry_t_vxlan_segment(p4info_helper,"downstream", sw=s3, ingress_port="\000\003", vni=0x100000)
        insert_table_entry_flow_cache(p4info_helper,"downstream", sw=s3, dst_ip_addr="10.0.1.1", outter_ip="192.168.0.31", port="\000\001")

        try:
            thread.start_new_thread(sniff_and_enqueue,())
            #thread.start_new_thread(get_k_lfu_rules,())
            #thread.start_new_thread(readTableRules_thread,(p4info_helper,s1,s2))     
            #thread.start_new_thread(plot_statistics,(p4info_helper,s1))

        except:
            print "Error: unable to start thread"
        while True:
            if not q.empty():
                pkt = q.get()
                #pkt.show2()
                if(pkt.haslayer(IP)):
                    src_ip = pkt.getlayer(IP).src
                    dst_ip = pkt.getlayer(IP).dst
                if(pkt.haslayer(VXLAN)):
                    decap_pkt = pkt.payload.payload.payload.payload
                    if(decap_pkt.haslayer(Ether)):
                        pkt_src_mac = decap_pkt.getlayer(Ether).src 
                        pkt_dst_mac = decap_pkt.getlayer(Ether).dst
                        ether_type = decap_pkt.getlayer(Ether).type
                        if ether_type == 2048 or ether_type == 2054:
                            if(decap_pkt.haslayer(IP)):
                                pkt_src_ip = decap_pkt.getlayer(IP).src
                                pkt_dst_ip = decap_pkt.getlayer(IP).dst
                                outter_ip = resolve_outter_ip(oracle,pkt_src_mac,pkt_dst_mac,s1,s2)
                                if(oracle[pkt_src_mac][3] == oracle[pkt_dst_mac][3]): #If the source and destination have the same VNI
                                    dst_ip_key = ip_to_insert(oracle,pkt_src_mac,pkt_dst_mac,s1,s2)
                                    egress_port = resolve_egress_port(oracle,pkt_src_mac,pkt_dst_mac,s1,s2)
                                    cache_handler(p4info_helper,s1,pkt_dst_ip)


        sys.stdout.flush()


    except KeyboardInterrupt:
        # using ctrl + c to exit
        print "Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    # Then close all the connections
    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    """ Simple P4 Controller
        Args:
            p4info:     指定 P4 Program 編譯產生的 p4info (PI 制定之格式、給予 controller 讀取)
            bmv2-json:  指定 P4 Program 編譯產生的 json 格式，依據 backend 不同，而有不同的檔案格式
     """

    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    # Specified result which compile from P4 program
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
            type=str, action="store", required=False,
            default="./simple.p4info")
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
            type=str, action="store", required=False,
            default="./simple.json")
    parser.add_argument('--my_topology', help='Topology JSON File',
            type=str, action="store", required=False,
            default="./simple.json")
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nPlease compile the target P4 program first." % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nPlease compile the target P4 program first." % args.bmv2_json
        parser.exit(1)
    q = Queue()
    flow_counter = {}
    p4_counters = {}
    table_rules = {}    #key = switch, value = [downstream,flow_table,match_ip,param_ip,param_port,counter]
    global_history = {}
    recent_history = {}
    threshold = 3
    cache_size = 20
    # Pass argument into main function
    main(args.p4info, args.bmv2_json, args.my_topology)