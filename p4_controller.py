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
import matplotlib.pyplot as plt
from scapy.all import *
import csv




THRESHOLD = 20
CACHE_SIZE = 20

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
    #print "Installed flow_cache entry via P4Runtime."

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
    #print "Deleted flow_cache entry via P4Runtime."

def delete_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32) #Change '32' to the desired prefix matc
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.DeleteTableEntry(table_entry)
    #print "Deleted flow_cache entry via P4Runtime."

def readTableRules(p4info_helper, sw, table_name):  
    #Reads the table entries from all tables on the switch.
    #TODO - Give the table id of the cache to the ReadTableEntries() function to read only from the cache
    table_id = p4info_helper.get_tables_id(table_name)
    rules = []
    for response in sw.ReadTableEntries(table_id=table_id):
        for entity in response.entities:
            entry = entity.table_entry
            splitted_table_name = table_name.split(".")
            param_port = 0
            param_ip = 0
            downstream = splitted_table_name[1]
            name = splitted_table_name[2]
            key_ip = socket.inet_ntoa(p4info_helper.get_match_field_value(entry.match[0])[0])
            mask = int(p4info_helper.get_match_field_value(entry.match[0])[1])
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            for p in action.params:
                param_name = p4info_helper.get_action_param_name(action_name, p.param_id)
                if(param_name == "dst_ip"):
                    param_ip = socket.inet_ntoa(p.value)
                else:
                    param_port = struct.unpack('>H', p.value)[0]
            rules.append([downstream,name,(key_ip,mask),param_ip,param_port,0])
    #Reads the counters entries from all table entries on the cache.
    for rule in rules:
        rule_ip = rule[2][0]
        rule_mask = rule[2][1]
        table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress.downstream1.flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (rule_ip,rule_mask)
        })
        for response in sw.ReadDirectCounter(table_entry = table_entry, table_id = table_id):
            for entity in response.entities:
                direct_counter_entry = entity.direct_counter_entry
                #print "The switch is: %s: %d packets" % (sw.name, direct_counter_entry.data.packet_count)
            rule[5] = int("%d"%( direct_counter_entry.data.packet_count))
    return rules

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

def plot_statistics(p4info_helper,sw1):
    sleep(560)
    stop_handler = True
    sleep(20)
    cmd = "stop$0.0.0.0"
    server_socket.send(cmd)
    sleep(20)
    rules = readTableRules(p4info_helper,sw1,"basic_tutorial_ingress.downstream1.flow_cache")
    flow_list = []
    rule_hits_list = []
    cache_time_list = []
    for rule in rules:
        global_history[rule[2]][0] +=  rule[5]
        global_history[rule[2]][4] +=  time.time() - global_history[rule[2]][3]

    new_global_history_hit_sort = sorted(global_history.items(), key=lambda x: x[1][0], reverse=True)
    for elem in new_global_history_hit_sort:
        flow_list.append(elem[0])
        rule_hits_list.append(elem[1][0])

    new_global_history_time_in_cache_sort = sorted(global_history.items(), key=lambda x: x[1][4], reverse=True)
    for elem in new_global_history_time_in_cache_sort:
        cache_time_list.append(elem[1][4])
    flow_index = list(range(len(cache_time_list)))

    with open('flow_stats.csv', 'w') as file:
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

def switch_insert_rule_cmd(rule):
    cmd = "insert$" + rule
    server_socket.send(cmd)
    recv_data = server_socket.recv(1024)
    recv_data = recv_data.split("$")
    if(len(recv_data) > 1 and recv_data[0] != "ack0"):
        splitted_rule = recv_data[1].split("'")
        rule_ip = splitted_rule[1]
        rule_mask = splitted_rule[2][2:4]
        recv_data[1] = (rule_ip,int(rule_mask))
    return recv_data
    
def rule_handler(p4info_helper,sw1,rule):
    if rule not in global_history:
        global_history[rule] = [1,False,time.time(),0,0,rule] #[Count, Is_in_cache, Arrival_time, Cache_insertion_time, Overall_time_in_cache, rule]  
        recent_history[rule] = 1
    else:
        if rule not in recent_history:
            recent_history[rule] = 1
        else:
            recent_history[rule] += 1
            if recent_history[rule] >= THRESHOLD:
                if(global_history[rule][1] == False):
                    if(len(rules_in_cache) < CACHE_SIZE):
                        res = switch_insert_rule_cmd(str(rule))
                        rules_in_cache.append([rule,0])
                        global_history[rule][1] = True
                        global_history[rule][3] = time.time()
                    else:
                        res = switch_insert_rule_cmd(str(rule))
                        if(len(res) > 2):
                            removed_rule = res[1]
                            removed_rule_counter = res[2]
                            global_history[removed_rule][0] += int(removed_rule_counter)
                            global_history[removed_rule][1] = False
                            for rule_in_cache in rules_in_cache:
                                if(rule_in_cache[0] == removed_rule):
                                    global_history[removed_rule][0] += rule_in_cache[1]
                                    rules_in_cache.remove(rule_in_cache)
                            global_history[removed_rule][4] += time.time() - global_history[removed_rule][3]
                            del recent_history[removed_rule]
                            global_history[rule][1] = True
                            rules_in_cache.append([rule,0])
                            global_history[rule][3] = time.time()
                # It is possible that a rule was already inserted, but packets that are supposed to hit that
                # rule have been already forwarded to the controller. Therefore, increment their value in the cache by 1
                else:
                    for i in range(len(rules_in_cache)):
                        if(rules_in_cache[i][0] == rule):
                            rules_in_cache[i][1] += 1

def insert_preliminary_rules(p4info_helper,s1,s2):

    ##### Insert flow rules for s1 #####


    #Ingress Upstream Rules - Switch 1

    insert_table_entry_t_vxlan_term(p4info_helper, sw=s1, dst_eth_addr="00:00:00:00:01:01")
    insert_table_entry_t_vxlan_term(p4info_helper, sw=s1, dst_eth_addr="00:00:00:00:01:02")
    insert_table_entry_t_forward_l2(p4info_helper, sw=s1, dst_eth_addr="00:00:00:00:01:01", port="\000\001") 
    insert_table_entry_t_forward_l2(p4info_helper, sw=s1, dst_eth_addr="00:00:00:00:01:02", port="\000\002")
    insert_table_entry_t_forward_underlay(p4info_helper, sw=s1, ip_dstAddr="192.168.0.100", port="\000\003") 
    insert_table_entry_t_forward_underlay(p4info_helper, sw=s1, ip_dstAddr="192.168.0.2", port="\000\004") 

    #Ingress Downstream rules - Switch 1 - Host 1

    insert_table_entry_t_controller(p4info_helper,"downstream1", sw=s1, key_port="\000\003", ip_dstAddr="192.168.0.100", param_port="\000\003")
    insert_table_entry_t_vtep(p4info_helper,"downstream1",sw=s1, src_eth_addr="00:00:00:00:01:01", vtep_ip="192.168.0.1")
    insert_table_entry_t_vxlan_segment(p4info_helper,"downstream1", sw=s1, ingress_port="\000\001", vni=0x100000)
    #insert_table_entry_flow_cache(p4info_helper,"downstream1", sw=s1, dst_ip_addr="10.0.1.2", outter_ip="0.0.0.0", port="\000\002")

    #Ingress Downstream rules - Switch 1 - Host 2

    insert_table_entry_t_controller(p4info_helper,"downstream2", sw=s1, key_port="\000\003", ip_dstAddr="192.168.0.100", param_port="\000\003")
    insert_table_entry_t_vtep(p4info_helper,"downstream2",sw=s1, src_eth_addr="00:00:00:00:01:02", vtep_ip="192.168.0.1")
    insert_table_entry_t_vxlan_segment(p4info_helper,"downstream2", sw=s1, ingress_port="\000\002", vni=0x100000)
    #insert_table_entry_flow_cache(p4info_helper,"downstream2", sw=s1, dst_ip_addr="10.0.1.1", outter_ip="0.0.0.0", port="\000\001")

    #Egress Downstream rules - Switch 1
    insert_table_entry_t_send_frame(p4info_helper, sw=s1, dst_ip_addr="192.168.0.2", smac="00:aa:00:01:00:02", dmac="00:aa:00:02:00:03")
    insert_table_entry_t_send_frame(p4info_helper, sw=s1, dst_ip_addr="192.168.0.100", smac="00:00:00:00:01:05", dmac="00:00:00:00:01:05")



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

def get_rule(pkt_dst_ip):
    ### TODO ###
    #Search the Policy object for a rule (ip + mask)
    #rule = Policy_object.seek_for_match(pkt_dst_ip)
    # returns a rule to be inserted to the switch
    rule_ip = pkt_dst_ip
    rule_mask = 32
    return(rule_ip,rule_mask)

def main(p4info_file_path, bmv2_file_path, my_topology):

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    try:

        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='192.168.0.5:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='192.168.0.2:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()

        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForardingPipelineConfig on s1"

        oracle  =  {"00:00:00:00:01:01":[s1,"10.0.1.1","\000\001",0x100000,1],#(MAC: [Switch,IP,Port,VNI,downstream_id])
                    "00:00:00:00:01:02":[s1,"10.0.1.2","\000\002",0x100000,2],
                    "00:00:00:00:02:03":[s2,"10.0.2.3","\000\001",0x100000,1],
                    "00:00:00:00:02:04":[s2,"10.0.2.4","\000\002",0x200000,2]
                    }
        insert_preliminary_rules(p4info_helper,s1,s2)
        server_socket.connect(("192.168.0.5", 50000))

        try:
            thread.start_new_thread(sniff_and_enqueue,())    
            thread.start_new_thread(plot_statistics,(p4info_helper,s1))

        except:
            print "Error: unable to start thread"
        while True:
            if not q.empty():
                pkt = q.get()
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
                                if(oracle[pkt_src_mac][3] == oracle[pkt_dst_mac][3]): #If the source and destination have the same VNI
                                    if stop_handler is False:
                                        rule_handler(p4info_helper,s1,get_rule(pkt_dst_ip))

        sys.stdout.flush()


    except KeyboardInterrupt:
        # using ctrl + c to exit
        print "Shutting down."
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
    global_history = {}
    recent_history = {}
    rules_in_cache = []
    stop_handler = False
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Pass argument into main function
    main(args.p4info, args.bmv2_json, args.my_topology)