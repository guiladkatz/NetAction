#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse, grpc, os, sys, json
import time
from time import sleep
import thread
import socket
import random as rnd
from scapy.all import *



# set our lib path
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '../../../utils/'))

CPU_ROLE_ID = 3
CACHE_NAME =  "basic_tutorial_ingress.downstream1.flow_cache"
stop_handler = False
entry_TTL_ns = 5000000000

CACHE_SIZE = 0
RANDOM_RULES_NUM = 8
EVICTION_THRESHOLD = 192
READ_COUNTER_INTERVAL = 0.5
PORT = 50101
LRU_REPLACEMENT_POLICY = False


# And then we import
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

 
def insert_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, rule, role_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (rule[0],rule[1])
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.WriteTableEntry_flowCache(table_entry,role_id=role_id)
    #print "Installed flow_cache drop entry via P4Runtime."

def delete_table_entry_flow_cache_drop(p4info_helper,downstream_id, sw, rule, role_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress." + downstream_id + ".flow_cache",
        match_fields = {
            "hdr.ipv4.dstAddr": (rule[0],rule[1])
        },
        action_name = "basic_tutorial_ingress." + downstream_id + ".drop")
    sw.DeleteTableEntry(table_entry,role_id=role_id)
    #print "Deleted flow_cache entry via P4Runtime."

def read_rnd_counters_flowCache(p4info_helper, sw, table_name, rules_in_cache, rnd_rules_num):
    table_entry_array = []
    random_rules_dict = {}
    random_rules = []
    if(len(rules_in_cache) > rnd_rules_num):
        random_rules = rnd.sample(rules_in_cache, k = rnd_rules_num)
    else:
        random_rules = rules_in_cache
    for rule in random_rules:
        #dst_ip_addr = rule[0]
        rule_ip = rule[0][0]
        rule_mask = rule[0][1]
        table_entry = p4info_helper.buildTableEntry(
        table_name = table_name,
        match_fields = {
            "hdr.ipv4.dstAddr": (rule_ip,rule_mask)
        })
        table_entry_array.append(table_entry)
    for response in sw.ReadTableEntries_batch(table_entry_arr = table_entry_array, table_id = p4info_helper.get_tables_id(table_name)):
        for entity in response.entities:
            entry = entity.table_entry
            packet_count = entry.counter_data.packet_count
            time_since_last_hit = entry.time_since_last_hit.elapsed_ns
            recv_rule = socket.inet_ntoa(entry.match[0].lpm.value)
            lru_val = is_lru(time_since_last_hit,entry_TTL_ns)
            random_rules_dict[recv_rule] = [int("%d"%(packet_count)),lru_val]

    return random_rules_dict

def is_lru(time_since_last_hit,TTL):
    if(time_since_last_hit == TTL):
        return True
    else:
        return False

def update_cache(p4info_helper, sw,client_delete):
    global stop_handler
    while(True):
        if(CACHE_SIZE != 0):
            try:
                sleep(READ_COUNTER_INTERVAL)
                if(stop_handler == False):
                    if len(flow_cache) > 3:
                        rnd_rules_and_counters_dict = read_rnd_counters_flowCache(p4info_helper, sw, CACHE_NAME, flow_cache, RANDOM_RULES_NUM)
                        for rule in rnd_rules_and_counters_dict.keys():
                            if rule in flow_cache_ips:
                                i = flow_cache_ips.index(rule)
                                flow_cache[i][1] = rnd_rules_and_counters_dict[flow_cache[i][0][0]][0]
                                flow_cache[i][2] = rnd_rules_and_counters_dict[flow_cache[i][0][0]][1]
                        evicted_rules_num = 0
                        del_cmd = "ack1"

                        while(len(flow_cache) >= EVICTION_THRESHOLD):
                            if LRU_REPLACEMENT_POLICY is True:
                                evicted_rule = get_lru(flow_cache)
                            else:
                                evicted_rule = get_lfru_rule(flow_cache)
                            if evicted_rule is not None:
                                evicted_rules_num+=1
                                delete_table_entry_flow_cache_drop(p4info_helper,"downstream1", sw, evicted_rule[0], CPU_ROLE_ID)
                                flow_cache.remove(evicted_rule)
                                flow_cache_ips.remove(evicted_rule[0][0])
                                global_history[evicted_rule[0]] += evicted_rule[1]
                                del_cmd += "$" + str(evicted_rule[0][0]) + "/" + str(evicted_rule[0][1]) + "/" + str(evicted_rule[1])
                        final_cmd = str(evicted_rules_num) + "$" + del_cmd
                        try:
                            client_delete.send(final_cmd)
                            client_delete.recv(1024)
                        except socket.error as msg:
                            print("In server_tcp_socket at recv The error msg is: ")
                            print(msg)
                            client_insert.close()
                            break


            except grpc.RpcError as e:
                #pass
                print("GRPC ERROR")
                printGrpcError(e)

def printGrpcError(e):
    print "gRPC Error: ", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print "[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def takeCounter(elem):
    return elem[1]
def handle_string(unsplitted_rule):
    splitted_rule = unsplitted_rule.split("'")
    rule_ip = splitted_rule[1]
    rule_mask = int(splitted_rule[2][2:4])
    return (rule_ip,rule_mask)

def server_tcp_socket(p4info_helper, sw, client_insert):
    global stop_handler
    while True:
        resp = "ack"
        data = ""
        try:
            data = client_insert.recv(1024)
            data = data.split("$")
        except socket.error as msg:
            print("In server_tcp_socket at recv The error msg is: ")
            print(msg)
            client_insert.close()
            break

        if(len(data) > 1):
            cmd = data[0]
            if(cmd != "stop"):
                data[1] = handle_string(data[1])
            new_rule = data[1]
            resp = "ack"
            if(cmd == "insert"):
                if stop_handler is False:
                    insert_table_entry_flow_cache_drop(p4info_helper,"downstream1", sw, new_rule, CPU_ROLE_ID)
                    flow_cache.append([new_rule,0,False])
                    flow_cache_ips.append(new_rule[0])
                    global_history[new_rule] = 0
                    resp += "0$"
            if(cmd == "stop"):
                stop_handler = True

        try:
            client_insert.send(resp)
        except socket.error as msg:
            print("In server_tcp_socket at send The error msg is: ")
            print(msg)
            client_insert.close()
            break
    client_insert.close()

def get_lfru_rule(flow_cache):
    lfru = None
    temp_cache = []
    temp_flow_cache = []
    if(len(flow_cache) > 0):
        temp_flow_cache = sorted(flow_cache,key=takeCounter)   
        #temp_flow_cache.sort(key=takeCounter)
        for rule in temp_flow_cache:
            if rule[2] is True:
                temp_cache.append(rule)
        if(len(temp_cache) > 0):
            temp_cache = sorted(temp_cache,key=takeCounter)
            #temp_cache.sort(key=takeCounter)
            lfru = temp_cache[0]
        else:
            lfru = temp_flow_cache[0]
    return lfru
def get_lru(flow_cache):
    lru = None
    lru_rules = []
    if(len(flow_cache) > 0):
        for rule in flow_cache:
            if rule[2] is True:
                lru_rules.append(rule)
        if(len(lru_rules) > 0):
            lru = lru_rules[0]
        else:
            lru = flow_cache[0]
    return lru

def main(p4info_file_path, bmv2_file_path, my_topology):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address='192.168.0.5:50051',
        device_id=0,
        proto_dump_file='logs/s1-cpu-p4runtime-requests.txt')

    s1.MasterArbitrationUpdate(role = CPU_ROLE_ID)
    welcome_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    welcome_socket.bind(('0.0.0.0', PORT))
    welcome_socket.listen(2)
    count = 0
    while (count < 2):
        if(count == 0):
            client_insert, addr_insert = welcome_socket.accept()
        if(count == 1):
            client_delete, addr_delete = welcome_socket.accept()
            if(CACHE_SIZE != 0):
                thread.start_new_thread(update_cache,(p4info_helper,s1,client_delete))
        count+=1


    if(CACHE_SIZE != 0):
        server_tcp_socket(p4info_helper,s1,client_insert)
    else:
        sleep(1000)

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
    parser.add_argument('--port', help='Socket Port',
            type=int, action="store", required=False,
            default=50001)
    parser.add_argument('--eviction_threshold', help='Above this threshold delete rules',
            type=int, action="store", required=False,
            default=48)
    parser.add_argument('--cache_size', help='Size of the cache',
            type=int, action="store", required=False,
            default=64)
    parser.add_argument('--random_rules_num', help='Random number of rules to sample counters',
            type=int, action="store", required=False,
            default=16)
    parser.add_argument('--read_counter_interval', help='time interval to sample counters from cache',
            type=float, action="store", required=False,
            default=1)
    """
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
    flow_cache_ips = []
    global_history = {}
    #RANDOM_RULES_NUM = args.random_rules_num
    #CACHE_SIZE = args.cache_size
    #EVICTION_THRESHOLD = args.eviction_threshold
    #READ_COUNTER_INTERVAL = args.read_counter_interval
    #PORT = args.port


    main(args.p4info, args.bmv2_json, args.my_topology)