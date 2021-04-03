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
import random as rnd
from scapy.all import *



# set our lib path
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '../../../utils/'))

CPU_ROLE_ID = 3
RANDOM_RULES_NUM = 10
CACHE_NAME =  "basic_tutorial_ingress.downstream1.flow_cache"
CACHE_SIZE = 20


# And then we import
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


def insert_table_entry_flow_cache(p4info_helper,downstream_id, sw, dst_ip_addr, outter_ip, port, election_id):
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
    sw.WriteTableEntry(table_entry,election_low=election_id)
    print "Installed flow_cache entry via P4Runtime."

def insert_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr, role_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.WriteTableEntry(table_entry,role_id=role_id)
    #print "Installed flow_cache drop entry via P4Runtime."

def insert_table_entry_lfu(p4info_helper,downstream_id, sw, dst_ip_addr, role_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".lfu",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.WriteTableEntry(table_entry, role_id=role_id)
    print "Installed lfu entry via P4Runtime."

def delete_table_entry_flow_cache(p4info_helper,downstream_id, sw, dst_ip_addr, outter_ip, port, election_id):
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
    sw.DeleteTableEntry(table_entry,election_low=election_id)
    print "Deleted flow_cache entry via P4Runtime."

def delete_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr, role_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.DeleteTableEntry(table_entry,role_id=role_id)
    #print "Deleted flow_cache entry via P4Runtime."

def delete_table_entry_lfu(p4info_helper,downstream_id, sw, dst_ip_addr, role_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".lfu",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.DeleteTableEntry(table_entry, role_id=role_id)
    print "Deleted lfu entry via P4Runtime."

def readTableRules_lfu(p4info_helper, sw, table_name):
    table_id = p4info_helper.get_tables_id(table_name)
    all_rules = []
    for response in sw.ReadTableEntries(table_id=table_id):
        for entity in response.entities:
            entry = entity.table_entry
            full_table_name = p4info_helper.get_tables_name(entry.table_id)
            table_name = full_table_name.split(".")
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

def readTableRules_flowCache(p4info_helper, sw, table_name):
    #Reads the table entries from all tables on the switch.
    table_id = p4info_helper.get_tables_id(table_name)
    rules = []
    rules_read_time_begin = time.time()
    for response in sw.ReadTableEntries(table_id=table_id):
        for entity in response.entities:
            entry = entity.table_entry
            table_name = table_name.split(".")
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
            rules.append([downstream,name,key_ip,param_ip,param_port])
    return rules

def read_rnd_counters_flowCache(p4info_helper, sw, table_name, rules_in_cache, rnd_rules_num):
    random_rules_dict = {}
    random_rules = []
    if(len(rules_in_cache) > rnd_rules_num):
        random_rules = rnd.sample(rules_in_cache, k = rnd_rules_num)
    else:
        random_rules = rules_in_cache
    for rule in random_rules:
        dst_ip_addr = rule[0]
        table_entry = p4info_helper.buildTableEntry(
        table_name = table_name,
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        })
        for response in sw.ReadDirectCounter(table_entry = table_entry, table_id = p4info_helper.get_tables_id(table_name)):
            for entity in response.entities:
                direct_counter_entry = entity.direct_counter_entry
                random_rules_dict[rule[0]] = int("%d"%( direct_counter_entry.data.packet_count))
    return random_rules_dict

def update_cache(p4info_helper, sw):
    sleep(0.15)
    if len(flow_cache) > 0:
        #rules_in_cache = readTableRules_flowCache(p4info_helper, sw, "basic_tutorial_ingress.downstream1.flow_cache")
        rnd_rules_and_counters_dict = read_rnd_counters_flowCache(p4info_helper, sw, CACHE_NAME, flow_cache, RANDOM_RULES_NUM)
        for i in range(len(flow_cache)):
            if flow_cache[i][0] in rnd_rules_and_counters_dict.keys():
                flow_cache[i][1] = rnd_rules_and_counters_dict[flow_cache[i][0]]

def printGrpcError(e):
    print "gRPC Error: ", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print "[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def takeCounter(elem):
    return elem[1]

def server_tcp_socket(p4info_helper, sw1):
    welcome_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    welcome_socket.bind(('0.0.0.0', 50000))
    welcome_socket.listen(1)
    client, addr = welcome_socket.accept()
    while 1:
        resp = "ack"
        data = client.recv(1024)
        data = data.split(",")
        if(len(data) > 1):
            cmd = data[0]
            new_rule = data[1]
            resp = "ack"
            if(cmd == "insert"):
                if(len(flow_cache) < CACHE_SIZE):
                    insert_table_entry_flow_cache_drop(p4info_helper,"downstream1", sw1, new_rule, CPU_ROLE_ID)
                    flow_cache.append([new_rule,0])
                    resp += "0,"
                else:    
                    lfu = get_lfu_rule()
                    if lfu is not None:
                        delete_table_entry_flow_cache_drop(p4info_helper,"downstream1", sw1, lfu[0], CPU_ROLE_ID)
                        flow_cache.remove(lfu)
                        insert_table_entry_flow_cache_drop(p4info_helper,"downstream1", sw1, new_rule, CPU_ROLE_ID)
                        flow_cache.append([new_rule,0])
                        resp = resp + "1," + lfu[0] + "," + str(lfu[1])

        #print(resp)
        client.send(resp)
        #print("Finished command")
    client.close()

def get_lfu_rule():
    lfu = None
    if(len(flow_cache) > 0):          
        flow_cache.sort(key=takeCounter)
        lfu = flow_cache[0]
    return lfu

def main(p4info_file_path, bmv2_file_path, my_topology):
    # Instantiate a P4Runtime helper from the p4info file
    # - then need to read from the file compile from P4 Program, which call .p4info
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    try:

        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='192.168.0.5:50051',
            device_id=0,
            proto_dump_file='logs/s1-cpu-p4runtime-requests.txt')

        # 傳送 master arbitration update message 來建立，使得這個 controller 成為
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate(role = CPU_ROLE_ID)
        thread.start_new_thread(server_tcp_socket,(p4info_helper,s1))
        thread.start_new_thread(update_cache,(p4info_helper,s1))
        sleep(10)

        while True:

            sleep(0.1)

            """
            new_flow_cache_rules = readTableRules_flowCache(p4info_helper,s1,"basic_tutorial_ingress.downstream1.flow_cache")

            if(len(new_flow_cache_rules) > 0):          
                new_flow_cache_rules.sort(key=takeCounter)
                new_lfu = new_flow_cache_rules[0]
                if(len(old_lfu_rules) > 0):
                    old_lfu = old_lfu_rules[0]
                    if(new_lfu[2] != old_lfu[2]):
                        insert_table_entry_lfu(p4info_helper,"downstream1", s1, str(new_lfu[2]),CPU_ROLE_ID)
                        delete_table_entry_lfu(p4info_helper,"downstream1", s1, str(old_lfu[2]),CPU_ROLE_ID)
                else:
                    insert_table_entry_lfu(p4info_helper,"downstream1", s1, str(new_lfu[2]),CPU_ROLE_ID)
            """
        sys.stdout.flush()


    except KeyboardInterrupt:
        # using ctrl + c to exit
        print "Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    # Then close all the connections
    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    """ Simple P4 Embedded Controller
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
    # Pass argument into main function
    flow_cache = []
    main(args.p4info, args.bmv2_json, args.my_topology)