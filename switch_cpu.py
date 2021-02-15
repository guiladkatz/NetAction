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
RANDOM_RULES_NUM = 5

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

def insert_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr, election_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.WriteTableEntry(table_entry,election_low=election_id)
    print "Installed flow_cache drop entry via P4Runtime."

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

def delete_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, dst_ip_addr, election_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (dst_ip_addr,32)
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.DeleteTableEntry(table_entry,election_low=election_id)
    print "Deleted flow_cache entry via P4Runtime."

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
    all_rules = []
    rules_read_time_begin = time.time()
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
                all_rules.append([downstream,name,key_ip,param_ip,param_port,0])
 
    if(len(all_rules) > RANDOM_RULES_NUM):
        random_rules = rnd.sample(all_rules, k = RANDOM_RULES_NUM)
    else:
        random_rules = all_rules
    for rule in random_rules:
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
            rule[5] = int("%d"%( direct_counter_entry.data.packet_count))
    return random_rules

def printGrpcError(e):
    print "gRPC Error: ", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print "[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def takeCounter(elem):
    return elem[5]

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

        while True:
            sleep(0.5)
            new_flow_cache_rules = readTableRules_flowCache(p4info_helper,s1,"basic_tutorial_ingress.downstream1.flow_cache")
            old_lfu_rules = readTableRules_lfu(p4info_helper,s1,"basic_tutorial_ingress.downstream1.lfu")

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
    main(args.p4info, args.bmv2_json, args.my_topology)