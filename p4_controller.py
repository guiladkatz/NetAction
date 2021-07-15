#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse, grpc, os, sys, json
import time
from time import sleep
import thread
from threading import Lock
import Queue
import socket
import struct
import pickle
import binascii
import matplotlib.pyplot as plt
from scapy.all import *
import csv




THRESHOLD = 64
CACHE_SIZE = 0
RANDOM_RULES_NUM = 8
RUN_TIME = 600
EVICTION_THRESHOLD = 192
PORT = 50101
inserts = []
deletes = []
inserts_count = 0
deletes_count = 0
sim_start_time = 0
packet_list = []
stop_handler = False

# set our lib path
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '../../../utils/'))

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
    print ("Installed t_vxlan_term entry via P4Runtime.")

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
    print ("Installed t_forward_l2 entry via P4Runtime.")

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
    print ("Installed t_forward_l2 entry via P4Runtime.")

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
    print ("Installed t_vxlan_segment_set_vni entry via P4Runtime.")

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
    #print ("Installed flow_cache entry via P4Runtime.")

def insert_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.WriteTableEntry(table_entry)
    print ("Installed flow_cache drop entry via P4Runtime.")

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
    print ("Installed t_vtep entry via P4Runtime.")

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
    print ("Installed t_controller entry via P4Runtime.")

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
    print ("Installed t_send_frame entry via P4Runtime.")

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
    #print ("Deleted flow_cache entry via P4Runtime.")

def delete_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32) #Change '32' to the desired prefix matc
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.DeleteTableEntry(table_entry)
    #print ("Deleted flow_cache entry via P4Runtime.")

def readTableRules(p4info_helper, sw, table_name):  
    #Reads the table entries from all tables on the switch.
    #TODO - Give the table id of the cache to the ReadTableEntries() function to read only from the cache
    table_id = p4info_helper.get_tables_id(table_name)
    rules = []
    for response in sw.ReadTableEntries(table_id=table_id):
        for entity in response.entities:
            entry = entity.table_entry
            key_ip = socket.inet_ntoa(p4info_helper.get_match_field_value(entry.match[0])[0])
            mask = int(p4info_helper.get_match_field_value(entry.match[0])[1])
            rules.append([(key_ip,mask),0])
    #Reads the counters entries from all table entries on the cache.
    for rule in rules:
        rule_ip = rule[0][0]
        rule_mask = rule[0][1]
        table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress.downstream1.flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (rule_ip,rule_mask)
        })
        for response in sw.ReadDirectCounter(table_entry = table_entry, table_id = table_id):
            for entity in response.entities:
                direct_counter_entry = entity.direct_counter_entry
            rule[1] = int("%d"%( direct_counter_entry.data.packet_count))
    return rules

def read_link_utilization_counter(p4info_helper, sw, link_util_array1, link_util_array2):
    global inserts
    global deletes
    global inserts_count
    global deletes_count
    global sim_start_time
    global packet_list
    global stop_handler

    filename_data = ""+str(CACHE_SIZE) + "_"+str(THRESHOLD)+"_"+str(RANDOM_RULES_NUM)+".txt"
    counter_name = "basic_tutorial_ingress.downstream1.flow_counter"
    entry_counter_name = "basic_tutorial_ingress.downstream1.entry_flow_counter"
    index = 0
    delta_count = 0
    interval = 0.5
    inc_interval = interval
    prev_counter = 0
    entry_prev_counter = 0
    prev_inserts_count = 0
    prev_deletes_count = 0
    sim_start_time = time.time()
    while(inc_interval < RUN_TIME):
        sleep(interval)
        curr_time = time.time()-sim_start_time
        for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                #print("Controller counter is")
                #print(int(counter.data.packet_count))
                delta_count = int(counter.data.packet_count) - prev_counter
                prev_counter = int(counter.data.packet_count)
                link_util_array1.append((curr_time,delta_count))
        for response in sw.ReadCounters(p4info_helper.get_counters_id(entry_counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                #print("Total counter is")
                #print(int(counter.data.packet_count))
                delta_count = int(counter.data.packet_count) - entry_prev_counter
                entry_prev_counter = int(counter.data.packet_count)
                link_util_array2.append((curr_time,delta_count))
        delta_count = inserts_count - prev_inserts_count
        prev_inserts_count = inserts_count
        inserts.append((curr_time,delta_count))

        delta_count = deletes_count - prev_deletes_count
        prev_deletes_count = deletes_count
        deletes.append((curr_time,delta_count))

        inc_interval+=interval
    stop_handler = True

    filename = "Experiments/simulation_data_"+filename_data
    with open(filename,'w') as filehandle1:
        filehandle1.write("Threshold = %s\n"%(str(THRESHOLD)))
        filehandle1.write("Cache Size = %s\n" % (str(CACHE_SIZE)))
        filehandle1.write("Simulation Run Time = %s\n" % (str(RUN_TIME)))
        filehandle1.write("Random Rules Num = %s\n" % (str(RANDOM_RULES_NUM)))
        filehandle1.write("Eviction Threshold = %s\n" % (str(EVICTION_THRESHOLD)))
        filehandle1.write("Traffic Details Are: \n")
        filehandle1.write("PACKET_LENGHT = 0.015625K = 16 KBytes Packets \n")
        filehandle1.write("BANDWIDTH = 10 Kbit/sec\n")


    filename = "Experiments_2_LFRU/link_utilization_"+filename_data
    with open(filename,'w') as filehandle1:
        for item in link_util_array1:
            filehandle1.write("%s\n" % (str(item)))
    
    filename = "Experiments_2_LFRU/traffic_arrival_rate_"+filename_data
    with open(filename,'w') as filehandle2:
        for item in link_util_array2:
            filehandle2.write("%s\n" % (str(item)))
    
    filename = "Experiments_2_LFRU/Insertions_"+filename_data
    with open(filename,'w') as filehandle2:
        final_insertions = inserts
        for item in final_insertions:
            filehandle2.write("%s\n" % (str(item)))

    filename = "Experiments_2_LFRU/Deletions_"+filename_data
    with open(filename,'w') as filehandle2:
        final_deletions = deletes
        for item in final_deletions:
            filehandle2.write("%s\n" % (str(item)))

    print("FINISH")

def printGrpcError(e):
    print ("gRPC Error: ", e.details())
    status_code = e.code()
    print ("(%s)" % status_code.name)
    traceback = sys.exc_info()[2]
    print ("[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def rawSniffer():
    global packet_list
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    count = 0
    timer = time.time()
    test = False
    while True:
        # creating a rawSocket for communications
        # PF_SOCKET (packet interface), SOCK_RAW (Raw socket) - htons (protocol) 0x08000 = IP Protocol

        # read a packet with recvfrom method
        pkt = rawSocket.recvfrom(2048) # tuple return
        #print(pkt)

        # Ethernet Header tuple segmentation
        eHeader = pkt[0][0:14]

        # parsing using unpack
        eth_hdr = struct.unpack("!6s6s2s", eHeader) # 6 dest MAC, 6 host MAC, 2 ethType

        # using hexify to convert the tuple value NBO into Hex format
        binascii.hexlify(eth_hdr[0])
        binascii.hexlify(eth_hdr[1])
        binascii.hexlify(eth_hdr[2])

        tcpHeader = pkt[0][34:54]
        tcp_hdr = struct.unpack("!HH16s", tcpHeader)

        #print "Source Source Port: %s" % tcp_hdr[0]
        #print "Source Destination Port: %s" % tcp_hdr[1]

        #print(type(tcp_hdr[1]))
        if tcp_hdr[1] == 4789:
            ipHeader = pkt[0][64:84]
            ip_hdr = struct.unpack("!12s4s4s", ipHeader) # 12s represents Identification, Time to Live, Protocol | Flags, Fragment Offset, Header Checksum
            ip_dest = socket.inet_ntoa(ip_hdr[2])
            q.put(ip_dest)
            #packet_new_list.append(ip_dest)
            #print "Source IP address %s" % socket.inet_ntoa(ip_hdr[1]) # network to ascii convertion
            #print "Destination IP address %s" % socket.inet_ntoa(ip_hdr[2]) # network to ascii convertion

        # unapck the TCP header (source and destination port numbers)    

def sniff_and_enqueue():

    while True:
        packets = sniff(iface="h5-eth0",filter="dst host 192.168.0.100",count=1)
        q.put(packets[0])

def plot_statistics(p4info_helper,sw1):
    sleep(RUN_TIME+1000)
    print("TESTTTTT")
    stop_handler = True
    sleep(20)
    cmd = "stop$0.0.0.0"
    server_socket_insert.send(cmd)
    sleep(20)
    rules = readTableRules(p4info_helper,sw1,"basic_tutorial_ingress.downstream1.flow_cache")
    rules_list = []
    rule_hits_list = []
    cache_time_list = []
    flow_id = []
    for rule in rules:
        global_history[rule[0]][0] +=  rule[1]
        global_history[rule[0]][4] +=  time.time() - global_history[rule[0]][3]

    new_global_history_hit_sort = sorted(global_history.items(), key=lambda x: x[1][0], reverse=True)
    for elem in new_global_history_hit_sort:
        rule_hits_list.append(elem[1][0])

    new_global_history_time_in_cache_sort = sorted(global_history.items(), key=lambda x: x[1][4], reverse=True)
    for elem in new_global_history_time_in_cache_sort:
        cache_time_list.append(elem[1][4])
    
    with open('flows_sorted_by_size.csv') as csvfile:
        count = 0
        flows_sorted_by_size = csv.reader(csvfile, quotechar='|')
        for flow in flows_sorted_by_size:
            if(count > 0):
                print(flow)
                rule = Policy[flow[1]]
                if rule not in rules_list:
                    rules_list.append(rule)
            else:
                count+=1

    print(rules_list)
    print("the lenght is:")
    print(len(rules_list))

    with open('rules_stats.csv', 'w') as file:
        writer = csv.writer(file)
        writer.writerow(["Hits", "Is_in_cache", "Arrival_time", "Cache_insertion_time", "Overall_time_in_cache"])
        writer.writerow(["After sorting by hit"])
        for rule in new_global_history_hit_sort:
            writer.writerow(rule)
        writer.writerow(["After sorting by time in cache"])
        for rule in new_global_history_time_in_cache_sort:
            writer.writerow(rule)


    title1 ="Cache Performance"

    fig1, (ax1,ax2) = plt.subplots(1,2)
    fig1.suptitle(title1)

    ax1.plot(rules_list,rule_hits_list)
    ax1.set_xlabel('Flow ID - Sorted by Size')
    ax1.set_ylabel('Number of Hits')
    ax1.set_title('Cache Hits')

    ax2.plot(rules_list,cache_time_list)
    ax2.set_xlabel('Flow ID - Sorted by Size')
    ax2.set_ylabel('Time in Cache')
    ax2.set_title('Time in Cache')

    fig1.show()
    plt.show()

def switch_insert_rule_cmd(rule):
    cmd = "insert$" + rule
    server_socket_insert.send(cmd)
    recv_data = server_socket_insert.recv(1024)
    recv_data = recv_data.split("$")
    if(len(recv_data) > 1 and recv_data[0] != "ack0"):
        splitted_rule = recv_data[1].split("'")
        rule_ip = splitted_rule[1]
        rule_mask = splitted_rule[2][2:4]
        recv_data[1] = (rule_ip,int(rule_mask))
    return recv_data

def recv_deleted_rule(server_socket_delete):
    global deletes
    global deletes_count
    global sim_start_time
    
    while(True):
        recv_data = ""
        evicted_rules_num = 0
        try:
            recv_data = server_socket_delete.recv(1024)
            server_socket_delete.send("ack")
        except socket.error as msg:
            print("in recv_deleted_rule The error msg is: ")
            print(msg)
            server_socket_delete.close()
            break
        recv_data = recv_data.split("$")
        if(CACHE_SIZE != 0):
            if (len(recv_data) > 0):
                evicted_rules_num = int(recv_data[0])
            if evicted_rules_num > 0:
                evicted_rules = recv_data[2:]
                for evicted_rule in evicted_rules:
                    deletes_count+=1
                    #deletes.append((time.time()-sim_start_time,evicted_rule))
                    splitted_rule = evicted_rule.split("/")
                    rule_ip = splitted_rule[0]
                    rule_mask = int(splitted_rule[1])
                    rule_counter = int(splitted_rule[2])
                    removed_rule = (rule_ip,int(rule_mask))

                    global_history[removed_rule][0] += rule_counter
                    global_history[removed_rule][1] = False
                    for rule_in_cache in rules_in_cache:
                        if(rule_in_cache[0] == removed_rule):
                            global_history[removed_rule][0] += rule_in_cache[1]
                            rules_in_cache.remove(rule_in_cache)
                    global_history[removed_rule][4] += time.time() - global_history[removed_rule][3]
                    del recent_history[removed_rule]
        
def rule_handler(p4info_helper,sw1,rule):
    global inserts
    global inserts_count
    global sim_start_time
    if rule not in global_history:
        global_history[rule] = [1,False,time.time(),0,0,rule] #[Count, Is_in_cache, Arrival_time, Cache_insertion_time, Overall_time_in_cache, rule]  
        recent_history[rule] = 1
    else:
        if rule not in recent_history:
            recent_history[rule] = 1
        else:
            recent_history[rule] += 1
            if recent_history[rule] > THRESHOLD:
                if(global_history[rule][1] == False):
                    res = switch_insert_rule_cmd(str(rule))
                    inserts_count+=1
                    #inserts.append((time.time()-sim_start_time,rule))
                    rules_in_cache.append([rule,0])
                    global_history[rule][1] = True
                    global_history[rule][3] = time.time()
                else:
                    global_history[rule][0] += 1

def insert_preliminary_rules(p4info_helper,sw):

    ##### Insert flow rules for sw #####


    #Ingress Upstream Rules - Switch 1

    insert_table_entry_t_vxlan_term(p4info_helper, sw=sw, dst_eth_addr="00:00:00:00:01:01")
    insert_table_entry_t_vxlan_term(p4info_helper, sw=sw, dst_eth_addr="00:00:00:00:01:02")
    insert_table_entry_t_forward_l2(p4info_helper, sw=sw, dst_eth_addr="00:00:00:00:01:01", port="\000\001") 
    insert_table_entry_t_forward_l2(p4info_helper, sw=sw, dst_eth_addr="00:00:00:00:01:02", port="\000\002")
    insert_table_entry_t_forward_underlay(p4info_helper, sw=sw, ip_dstAddr="192.168.0.100", port="\000\003") 
    insert_table_entry_t_forward_underlay(p4info_helper, sw=sw, ip_dstAddr="192.168.0.2", port="\000\004") 
    insert_table_entry_flow_cache(p4info_helper,"downstream2", sw=sw, dst_ip_addr="192.168.0.100", outter_ip="0.0.0.0", port="\000\003")

    #Ingress Downstream rules - Switch 1 - Host 1

    insert_table_entry_t_controller(p4info_helper,"downstream1", sw=sw, key_port="\000\003", ip_dstAddr="192.168.0.100", param_port="\000\003")
    insert_table_entry_t_vtep(p4info_helper,"downstream1",sw=sw, src_eth_addr="00:00:00:00:01:01", vtep_ip="192.168.0.1")
    insert_table_entry_t_vxlan_segment(p4info_helper,"downstream1", sw=sw, ingress_port="\000\001", vni=0x100000)
    #insert_table_entry_flow_cache(p4info_helper,"downstream1", sw=sw, dst_ip_addr="10.0.1.2", outter_ip="0.0.0.0", port="\000\002")

    #Ingress Downstream rules - Switch 1 - Host 2

    insert_table_entry_t_controller(p4info_helper,"downstream2", sw=sw, key_port="\000\003", ip_dstAddr="192.168.0.100", param_port="\000\003")
    insert_table_entry_t_vtep(p4info_helper,"downstream2",sw=sw, src_eth_addr="00:00:00:00:01:02", vtep_ip="192.168.0.1")
    insert_table_entry_t_vxlan_segment(p4info_helper,"downstream2", sw=sw, ingress_port="\000\002", vni=0x100000)
    #insert_table_entry_flow_cache(p4info_helper,"downstream2", sw=sw, dst_ip_addr="10.0.1.1", outter_ip="0.0.0.0", port="\000\001")

    #Egress Downstream rules - Switch 1
    insert_table_entry_t_send_frame(p4info_helper, sw=sw, dst_ip_addr="192.168.0.2", smac="00:aa:00:01:00:02", dmac="00:aa:00:02:00:03")
    insert_table_entry_t_send_frame(p4info_helper, sw=sw, dst_ip_addr="192.168.0.100", smac="00:00:00:00:01:05", dmac="00:00:00:00:01:05")


    """
    ##### Insert flow rules for s2 #####

    #Ingress Upstream Rules - Switch 2

    insert_table_entry_t_vxlan_term(p4info_helper, sw=s2, dst_eth_addr="00:00:00:00:02:03")
    insert_table_entry_t_vxlan_term(p4info_helper, sw=s2, dst_eth_addr="00:00:00:00:02:04")
    insert_table_entry_t_forward_l2(p4info_helper, sw=s2, dst_eth_addr="00:00:00:00:02:03", port="\000\001") 
    insert_table_entry_t_forward_l2(p4info_helper, sw=s2, dst_eth_addr="00:00:00:00:02:04", port="\000\002")
    insert_table_entry_t_forward_underlay(p4info_helper, sw=s2, ip_dstAddr="192.168.0.100", port="\000\003") 
    insert_table_entry_t_forward_underlay(p4info_helper, sw=s2, ip_dstAddr="192.168.0.1", port="\000\003") 

    #Ingress Downstream rules - Switch 2 - Host 3 - VNI
    insert_table_entry_t_controller(p4info_helper,"downstream1", sw=s2, key_port="\000\003", ip_dstAddr="192.168.0.100", param_port="\000\003")
    insert_table_entry_t_vtep(p4info_helper,"downstream1",sw=s2, src_eth_addr="00:00:00:00:02:03", vtep_ip="192.168.0.2")
    insert_table_entry_t_vxlan_segment(p4info_helper,"downstream1", sw=s2, ingress_port="\000\001", vni=0x100000)

    #Ingress Downstream rules - Switch 2 - Host 4 - VNI
    insert_table_entry_t_controller(p4info_helper,"downstream2", sw=s2, key_port="\000\003", ip_dstAddr="192.168.0.100", param_port="\000\003")
    insert_table_entry_t_vtep(p4info_helper,"downstream2",sw=s2, src_eth_addr="00:00:00:00:02:04", vtep_ip="192.168.0.2")
    insert_table_entry_t_vxlan_segment(p4info_helper,"downstream2", sw=s2, ingress_port="\000\002", vni=0x200000)
    
    #Egress Downstream rules - Switch 2
    insert_table_entry_t_send_frame(p4info_helper, sw=s2, dst_ip_addr="192.168.0.1", smac="00:aa:00:02:00:03", dmac="00:aa:00:01:00:02")
    insert_table_entry_t_send_frame(p4info_helper, sw=s2, dst_ip_addr="192.168.0.100", smac="00:aa:00:02:00:03", dmac="00:aa:00:01:00:02")
    """

def get_rule(pkt_dst_ip):
    if pkt_dst_ip in Policy:
        rule = Policy[pkt_dst_ip]
        if "." in rule:
            rule = rule.split("/")
            rule_ip = rule[0]
            rule_mask = int(rule[1])
            return(rule_ip,rule_mask)
    else:
        print("FAILED")

def main(p4info_file_path, bmv2_file_path, my_topology):
    global packet_list

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    try:

        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='sw',
            address='192.168.0.5:50051',
            device_id=0,
            proto_dump_file='logs/sw-p4runtime-requests.txt')

        sw.MasterArbitrationUpdate()

        sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)
        print ("Installed P4 Program using SetForardingPipelineConfig on sw")

        oracle  =  {"00:00:00:00:01:01":[sw,"10.0.1.1","\000\001",0x100000,1],#(MAC: [Switch,IP,Port,VNI,downstream_id])
                    "00:00:00:00:01:02":[sw,"10.0.1.2","\000\002",0x100000,2]
                    }
        insert_preliminary_rules(p4info_helper,sw)
        server_socket_insert.connect(("192.168.0.5", PORT))
        sleep(1)
        server_socket_delete.connect(("192.168.0.5", PORT))

        try:
            
            thread.start_new_thread(rawSniffer,())    
            #thread.start_new_thread(plot_statistics,(p4info_helper,sw))
            #sleep(1000)
            thread.start_new_thread(recv_deleted_rule,(server_socket_delete,))
            #thread.start_new_thread(read_link_utilization_counter,(p4info_helper, sw, link_util_array))

        except:
           print ("Error: unable to start thread")
        start_measure_flag = False
        while True:
            if not q.empty():
                pkt_dst_ip = q.get()
                if stop_handler is False:
                    rule = get_rule(pkt_dst_ip)
                    if rule is not None:
                        if start_measure_flag is False:
                            thread.start_new_thread(read_link_utilization_counter,(p4info_helper, sw, link_util_array1,link_util_array2))
                            start_measure_flag = True
                        if (CACHE_SIZE != 0):
                            rule_handler(p4info_helper,sw,rule)

                """
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
                                packet_list.append(pkt_dst_ip)
                                if(oracle[pkt_src_mac][3] == oracle[pkt_dst_mac][3]): #If the source and destination have the same VNI
                                    if stop_handler is False:
                                        rule = get_rule(pkt_dst_ip)
                                        if rule is not None:
                                            if start_measure_flag is False:
                                                thread.start_new_thread(read_link_utilization_counter,(p4info_helper, sw, link_util_array1,link_util_array2))
                                                #with open('test2.txt', 'w') as t_file:
                                                #    t_file.write("Thread started succesfully")
                                            start_measure_flag = True
                                            #try:
                                            #rule_handler(p4info_helper,sw,rule)
                                            #except socket.error as msg:
                                            #    print("in switch_insert_rule_cmd The error msg is: ")
                                            #    print(msg)
                                            #    server_socket_insert.close()
                                            #    break
                """
        sys.stdout.flush()


    except KeyboardInterrupt:
        # using ctrl + c to exit
        print ("Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    # Then close all the connections
    ShutdownAllSwitchConnections()


if __name__ == '__main__':

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

    """
    parser.add_argument('--threshold', help='Packet Miss Threshold',
            type=int, action="store", required=False,
            default=100)
    parser.add_argument('--cache_size', help='Switchs Cache Size',
            type=int, action="store", required=False,
            default=64)
    parser.add_argument('--random_rules_num', help='Random number of rules sample at Switchs CPU',
            type=int, action="store", required=False,
            default=1)
    parser.add_argument('--run_time', help='Simulation Time',
            type=int, action="store", required=False,
            default=5)
    parser.add_argument('--port', help='Socket Port',
            type=int, action="store", required=False,
            default=50001)
    """
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print ("\np4info file not found: %s\nPlease compile the target P4 program first." % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print ("\nBMv2 JSON file not found: %s\nPlease compile the target P4 program first." % args.bmv2_json)
        parser.exit(1)
    q = Queue()
    global_history = {}
    recent_history = {}
    rules_in_cache = []
    sim_start_time = 0
    link_util_array1 = []
    link_util_array1.append((0,0))
    link_util_array2 = []
    link_util_array2.append((0,0))
    server_socket_insert = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket_delete = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #THRESHOLD = args.threshold
    #CACHE_SIZE = args.cache_size
    #RANDOM_RULES_NUM = args.random_rules_num
    #RUN_TIME = args.run_time
    #PORT = args.port 



    with open('flow_rule_dict.pickle', 'rb') as handle:
        Policy = pickle.load(handle)
    for key in Policy:
        new_key = str(key)
        new_val = str(Policy[key])
        del Policy[key]
        Policy[new_key] = new_val

    # Pass argument into main function
    main(args.p4info, args.bmv2_json, args.my_topology)