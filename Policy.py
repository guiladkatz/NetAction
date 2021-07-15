#!/usr/bin/env python

"""
Cache Simulator Project
Copyright(c) 2020-2021
This program is free software; you can redistribute it and/or modify it
under the terms and conditions of the GNU General Public License,
version 2, as published by the Free Software Foundation.
This program is distributed in the hope it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.
You should have received a copy of the GNU General Public License along
with this program.  If not, see <http://www.gnu.org/licenses/>.
The full GNU General Public License is included in this distribution in
the file called "COPYING".
Contact Information:
Erez Alfasi <erez8272@gmail.com>
Itamar Gozlan <itamar.goz@gmail.com>
"""

from cidr_trie import PatriciaTrie
import urllib.request
import ipaddress
import random
import re
import json
import csv


class Policy(object):
    def __init__(self, url, routing_table_json_file=None):
        self.url = url
        self.sorted_prefix_length = []
        self.sorted_prefix_mask = []
        self.policy_ptrie = PatriciaTrie()
        self.new_policy_ptrie = PatriciaTrie()
        if routing_table_json_file:
            with open(routing_table_json_file) as f:
                data = json.load(f)
                self.routing_table = {ipaddress.ip_network(ip): int(data[ip]) for ip in data}
        else:
            self.routing_table = dict()
        self.build_trie()

    def init_subnets(self):
        pattern = re.compile(r'<a[^>]*>([^<]+)</a>')
        with urllib.request.urlopen(self.url) as response:
            page = response.read()
            html = page.decode('ISO-8859-1')
            html = html.split("Aggregation Suggestion")[2]
            html = html.split("RIR alloc")[0]
        for line in html.split('\n'):
            ip = re.findall(pattern, line)
            if ip and line.find("red") == -1:  # Insert the minimal rules, without aggregated ones
                self.routing_table[ipaddress.ip_network(ip[0].strip())] = random.randint(1, 64)  # (IP, ACTION_PORT)

    def save_policy_json(self, path):
        with open(path, 'w+') as outfile:
            json.dump({str(rule): self.routing_table[rule] for rule in self.routing_table}, outfile)

    def get_random_subnet(self):
        return random.choice(list(self.routing_table.keys()))

    def get_random_ip(self, prefix=None):
        if prefix is not None:
            return random.choice(list(prefix.hosts()))

        ip_network = random.choice(list(self.routing_table.keys()))
        return random.choice(list(ip_network.hosts()))

    def seek_for_match2(self, ip):
        rule, action = None, None
        ip_to_subnet = ipaddress.ip_network(str(ip) + '/32')
        for subnet in self.routing_table.keys():
            if ip_to_subnet.subnet_of(subnet):
                if rule is None:
                    rule = subnet
                    action = self.routing_table[subnet]
                else:
                    if subnet.prefixlen > rule.prefixlen:
                        rule = subnet
                        action = self.routing_table[subnet]

        return rule, action

    def build_trie(self):
        for network in self.routing_table:
            self.policy_ptrie.insert(str(network), self.routing_table[network])
        
    def seek_for_match(self, ip):
        nodes = self.policy_ptrie.find_all(str(ip))
        if nodes:
            return ipaddress.ip_network(nodes[-1][0]), nodes[-1][1]
        return None, None

    def seek_for_match_new(self, ip):
        nodes = self.new_policy_ptrie.find_all(str(ip))
        if nodes:
            return ipaddress.ip_network(nodes[-1][0]), nodes[-1][1]
        return None, None

    def get_dependencies(self, rule):
        dependencies = []
        rule = str(rule)
        node_f = self.policy_ptrie.find(rule)
        main_net = ipaddress.ip_network(rule)
        if node_f is not None:
            for node in self.policy_ptrie.traverse_preorder_from_node(node_f):
                if node == node_f:
                    continue
                for mask in node.masks:
                    node_net = ipaddress.ip_network(str(ipaddress.ip_network(node.ip)).split("/")[0] + "/" + str(mask))
                    if node_net.subnet_of(main_net):
                        dependencies.append(str(node_net))
        return dependencies
    
    def get_new_dependencies(self, rule):
        dependencies = []
        rule_ip = rule.split("/")[0]
        rule_mask = rule.split("/")[1]
        rule_ip_add = ipaddress.ip_network(rule_ip + "/" + rule_mask)
        for node in self.policy_ptrie.traverse_preorder():
            node_ip = str(ipaddress.IPv4Address(node.ip))
            if not node_ip == "0.0.0.0":
                node_mask = str(list(node.masks.keys())[0])
                if(int(node_mask) > int(rule_mask)):
                    node_rule = ipaddress.ip_network(node_ip + "/" + node_mask)
                    if node_rule.subnet_of(rule_ip_add):
                        dependencies.append(str(node_rule))
        return sort_by_mask(dependencies)

    def bits_to_ip(self,bit_string):
        return str(ipaddress.IPv4Address(int(bit_string, 2)))
        
    def build_extended_trie(self):
        trie = []
        extended_trie = []
        for node in self.policy_ptrie.traverse_preorder():
            rule_ip = str(ipaddress.IPv4Address(node.ip))
            if not rule_ip == "0.0.0.0":
                rule_mask = str(list(node.masks.keys())[0])
                rule = rule_ip + "/" + rule_mask
                action = str(list(node.masks.values())[0])
                deps = self.get_new_dependencies(rule)
                num_of_deps = len(deps)
                trie.append([rule_ip,rule_mask,action,num_of_deps])
        
        trie.sort(key=take_fourth_elem)
        new_rules_counter = 0
        for old_node in trie:
            old_node_ip = old_node[0]
            old_node_mask = old_node[1]
            old_node_action = old_node[2]
            old_node_num_of_deps = old_node[3]
            old_node_ip_bits = "".join(f"{i:08b}" for i in ipaddress.IPv4Address(old_node_ip).packed)
            if(old_node_num_of_deps == 0):
                new_rule = old_node_ip + "/" + old_node_mask
                if is_exist(new_rule,extended_trie) == False:
                    new_rules_counter += 1
                    extended_trie.append((new_rule,old_node_action))
            else:
                deps = self.get_new_dependencies("" + old_node_ip + "/" + old_node_mask)
                for dep in deps:
                    dep_ip = dep.split("/")[0]
                    dep_mask = dep.split("/")[1]
                    dep_lenght = int(dep_mask) - int(old_node_mask)
                    dep_ip_bits = "".join(f"{i:08b}" for i in ipaddress.IPv4Address(dep_ip).packed)
                    sun_num_of_deps = len(self.get_new_dependencies(dep))

                    curr_node_ip = dep.split("/")[0]
                    curr_node_mask = dep.split("/")[1]
                    curr_node_ip_bits = "".join(f"{i:08b}" for i in ipaddress.IPv4Address(dep_ip).packed)
                    father_bits = curr_node_ip_bits[:int(curr_node_mask)-1] + "0" + curr_node_ip_bits[int(curr_node_mask):]
                    father_mask = str(int(curr_node_mask)-1)
                    father_ip = self.bits_to_ip(father_bits)

                    for i in range(dep_lenght):
                        father_rule = father_ip + "/" + father_mask
                        father_deps = self.get_new_dependencies(father_rule)
                        father_num_of_deps = len(father_deps)
                        mask_diff = int(dep_mask) - int(father_mask)
                        if (father_num_of_deps == sun_num_of_deps) or (father_num_of_deps == sun_num_of_deps +1 and mask_diff == 1):

                            if(curr_node_ip_bits[int(curr_node_mask)-1] == '0'):
                                new_ip_bits = curr_node_ip_bits[:int(curr_node_mask)-1] + "1" + curr_node_ip_bits[int(curr_node_mask):]
                            else:
                                new_ip_bits = curr_node_ip_bits[:int(curr_node_mask)-1] + "0" + curr_node_ip_bits[int(curr_node_mask):]

                            new_mask = curr_node_mask
                            new_ip = self.bits_to_ip(new_ip_bits)
                            new_rule = new_ip + "/" + new_mask
                            if is_exist(new_rule,extended_trie) == False:
                                extended_trie.append((new_rule,old_node_action))
                                new_rules_counter+=1
                        curr_node_mask = father_mask
                        curr_node_ip_bits = father_bits
                        father_bits = curr_node_ip_bits[:int(curr_node_mask)-1] + "0" + curr_node_ip_bits[int(curr_node_mask):]
                        father_mask = str(int(curr_node_mask)-1)
                        father_ip = self.bits_to_ip(father_bits)
                        sun_num_of_deps = father_num_of_deps

        for new_rule in extended_trie:
            self.new_policy_ptrie.insert(new_rule[0],new_rule[1])

        new_rules_num = len(extended_trie)-len(trie)
        #print("The number of rules in the old trie is %d"%(len(trie)))
        #print("The number of rules in the new trie is %d"%(len(extended_trie)))
        #print("The number of new rules is: %d"%(new_rules_num))
        return [len(trie), len(extended_trie), new_rules_num]


def take_fourth_elem(elem):
    return elem[3]
def take_second_elem(elem):
    return elem[1]
def sort_by_mask(deps):
    new_deps_list = []
    sorted_deps= []
    for dep in deps:
        new_dep_list = dep.split('/')
        new_deps_list.append(new_dep_list)
    new_deps_list.sort(key=take_second_elem)
    for dep_list in new_deps_list:
        dep = "/".join(dep_list)
        sorted_deps.append(dep)
    return sorted_deps
def is_exist(rule, rules_arr):
    new_arr = []
    for old_rule in rules_arr:
        new_arr.append(old_rule[0])
    if rule in new_arr:
        return True
    else:
        return False

def create_policy(url):
    p = Policy(url)
    p.init_subnets()

    # Building the cidr-trie
    p.build_trie()
    return p.build_extended_trie()


def main():

    data = []
    f = open('Policies.txt','r')
    count = 0
    for line in f.readlines():
        res = create_policy(line)
        res.append(line[:-1])
        data.append(res)

    f.close()
    with open('Policies_data.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Old Trie Size", "New Trie Size", "Number of New Rules","URL"])
        for val in data:
            writer.writerow(val)


if __name__ == "__main__":
    main()
