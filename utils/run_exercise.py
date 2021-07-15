#!/usr/bin/env python2
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Adapted by Robert MacDavid (macdavid@cs.princeton.edu) from scripts found in
# the p4app repository (https://github.com/p4lang/p4app)
#
# We encourage you to dissect this script to better understand the BMv2/Mininet
# environment used by the P4 tutorial.
#
import os, sys, json, subprocess, re, argparse
from time import sleep

from p4_mininet import P4Switch, P4Host, P4HostV6, P4RuntimeSwitch

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.node import RemoteController


import p4runtime_lib.simple_controller

def configureP4Switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print '====================================='
                print 'Switch Device ID: %s' % str(self.device_id)
                print 'Switch CPU port: %s' % str(self.cpu_port)
                print "%s -> gRPC port: %d" % (self.name, self.grpc_port)

        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(switch_args)
                kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
                ConfiguredP4Switch.next_thrift_port += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> Thrift port: %d" % (self.name, self.thrift_port)

        return ConfiguredP4Switch


class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
        A custom class is used because the exercises make a few topology
        assumptions, mostly about the IP and MAC addresses.
    """
    def __init__(self, hosts, switches, links, log_dir, host_mode, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []
        self.sw_port_mapping = {}

        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)
            else:
                switch_links.append(link)

        link_sort_key = lambda x: x['node1'] + x['node2']
        # Links must be added in a sorted order so bmv2 port numbers are predictable
        host_links.sort(key=link_sort_key)
        switch_links.sort(key=link_sort_key)

        for sw in switches:
            self.addSwitch(sw, log_file="%s/%s.log" %(log_dir, sw))

        if host_mode is 4:
            for link in host_links:
                host_name = link['node1']
                host_sw   = link['node2']
                host_num = int(host_name[1:])
                sw_num   = int(host_sw[1:])
                host_ip = "10.0.%d.%d" % (sw_num, host_num)
                host_mac = '00:00:00:00:%02x:%02x' % (sw_num, host_num)
                # Each host IP should be /24, so all exercise traffic will use the
                # default gateway (the switch) without sending ARP requests.
                self.addHost(host_name, ip=host_ip+'/24', mac=host_mac)
                self.addLink(host_name, host_sw,
                            delay=link['latency'], bw=link['bandwidth'],
                            addr1=host_mac, addr2=host_mac)
                self.addSwitchPort(host_sw, host_name)
        if host_mode is 6:
            for link in host_links:
                host_name = link['node1']
                host_sw   = link['node2']
                host_num = int(host_name[1:])
                sw_num   = int(host_sw[1:])
                host_ip = "10.0.%d.%d" % (sw_num, host_num)
                host_ipv6 = '1000::%d:%d' % (sw_num, host_num)
                host_mac = '00:00:00:00:%02x:%02x' % (sw_num, host_num)
                # Each host IP should be /24, so all exercise traffic will use the
                # default gateway (the switch) without sending ARP requests.
                self.addHost(host_name, ip=host_ip+'/24', v6Addr=host_ipv6+'/64', mac=host_mac)
                self.addLink(host_name, host_sw,
                            delay=link['latency'], bw=link['bandwidth'],
                            addr1=host_mac, addr2=host_mac)
                self.addSwitchPort(host_sw, host_name)
        

        for link in switch_links:
            self.addLink(link['node1'], link['node2'],
                        delay=link['latency'], bw=link['bandwidth'])
            self.addSwitchPort(link['node1'], link['node2'])
            self.addSwitchPort(link['node2'], link['node1'])

        self.printPortMapping()

    def addSwitchPort(self, sw, node2):
        if sw not in self.sw_port_mapping:
            self.sw_port_mapping[sw] = []
        portno = len(self.sw_port_mapping[sw])+1
        self.sw_port_mapping[sw].append((portno, node2))

    def printPortMapping(self):
        print "Switch port mapping:"
        for sw in sorted(self.sw_port_mapping.keys()):
            print "%s: " % sw,
            for portno, node2 in self.sw_port_mapping[sw]:
                print "%d:%s\t" % (portno, node2),
            print


class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages

            hosts    : list<string>       // list of mininet host names
            switches : dict<string, dict> // mininet host names and their associated properties
            links    : list<dict>         // list of mininet link properties

            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary

            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance

            host_mode: integer  // IPv4/IPv6 specification
    """
    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def formatLatency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, (str, unicode)):
            return l
        else:
            return str(l) + "ms"


    def __init__(self, topo_file, log_dir, pcap_dir,
                       switch_json, bmv2_exe='simple_switch', quiet=False, host_mode=4,
                       threshold=100, cache_size=64, random_rules_num=1, run_time=600, port=50001,
                       eviction_threshold=48, read_counter_interval=1):
        """ Initializes some attributes and reads the topology json. Does not
            actually run the exercise. Use run_exercise() for that.

            Arguments:
                topo_file : string    // A json file which describes the exercise's
                                         mininet topology.
                log_dir  : string     // Path to a directory for storing exercise logs
                pcap_dir : string     // Ditto, but for mininet switch pcap files
                switch_json : string  // Path to a compiled p4 json for bmv2
                bmv2_exe    : string  // Path to the p4 behavioral binary
                quiet : bool          // Enable/disable script debug messages
        """

        self.quiet = quiet
        self.logger('Reading topology file.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.hosts = topo['hosts']
        self.switches = topo['switches']
        self.links = self.parse_links(topo['links'])

        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe
        # IPv4/6
        self.host_mode = host_mode
        self.threshold = threshold
        self.cache_size = cache_size
        self.random_rules_num = random_rules_num
        self.run_time = run_time
        self.port = port
        self.eviction_threshold = eviction_threshold
        self.read_counter_interval = read_counter_interval


    def run_exercise(self):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.start()
        sleep(1)

        # some programming that must happen after the net has started
        self.program_hosts()
        self.program_switches()

        # wait for that to finish. Not sure how to do this better
        sleep(1)

        self.do_net_cli()
        print("Exiting Mininet")
        # stop right after the CLI is exited
        self.net.stop()


    def parse_links(self, unparsed_links):
        """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions
            into dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s,t = t,s

            link_dict = {'node1':s,
                        'node2':t,
                        'latency':'0ms',
                        'bandwidth':None
                        }
            if len(link) > 2:
                link_dict['latency'] = self.formatLatency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(link_dict['node2'])
            links.append(link_dict)
        return links


    def create_network(self):
        """ Create the mininet network object, and store it as self.net.

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.net
        """
        self.logger("Building mininet topology.")

        self.topo = ExerciseTopo(self.hosts, self.switches.keys(), self.links, self.log_dir,self.host_mode)

        switchClass = configureP4Switch(
                sw_path=self.bmv2_exe,
                json_path=self.switch_json,
                log_console=True,
                pcap_dump=self.pcap_dir)

        if self.host_mode is 4:
            self.net = Mininet(topo = self.topo,
                        link = TCLink,
                        host = P4Host,
                        switch = switchClass,
                        controller = None)
        if self.host_mode is 6:
            self.net = Mininet(topo = self.topo,
                        link = TCLink,
                        host = P4HostV6,
                        switch = switchClass,
                        controller = None)

    def program_switch_p4runtime(self, sw_name, sw_dict):
        """ This method will use P4Runtime to program the switch using the
            content of the runtime JSON file as input.
        """
        sw_obj = self.net.get(sw_name)
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        runtime_json = sw_dict['runtime_json']
        self.logger('Configuring switch %s using P4Runtime with file %s' % (sw_name, runtime_json))
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/%s-p4runtime-requests.txt' %(self.log_dir, sw_name)
            p4runtime_lib.simple_controller.program_switch(
                addr='127.0.0.1:%d' % grpc_port,
                device_id=device_id,
                sw_conf_file=sw_conf_file,
                workdir=os.getcwd(),
                proto_dump_fpath=outfile)

    def program_switch_cli(self, sw_name, sw_dict):
        """ This method will start up the CLI and use the contents of the
            command files as input.
        """
        cli = 'simple_switch_CLI'
        # get the port for this particular switch's thrift server
        sw_obj = self.net.get(sw_name)
        thrift_port = sw_obj.thrift_port

        cli_input_commands = sw_dict['cli_input']
        self.logger('Configuring switch %s with file %s' % (sw_name, cli_input_commands))
        with open(cli_input_commands, 'r') as fin:
            cli_outfile = '%s/%s_cli_output.log'%(self.log_dir, sw_name)
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen([cli, '--thrift-port', str(thrift_port)],
                                 stdin=fin, stdout=fout)

    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for sw_name, sw_dict in self.switches.iteritems():
            if 'cli_input' in sw_dict:
                self.program_switch_cli(sw_name, sw_dict)
            if 'runtime_json' in sw_dict:
                self.program_switch_p4runtime(sw_name, sw_dict)

    def program_hosts(self):
        """ Adds static ARP entries and default routes to each mininet host.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for host_name in self.topo.hosts():
            h = self.net.get(host_name)
            h_iface = h.intfs.values()[0]
            link = h_iface.link
            sw_iface = link.intf1 if link.intf1 != h_iface else link.intf2
            # phony IP to lie to the host about
            host_id = int(host_name[1:])
            sw_ip = '10.0.%d.254' % host_id
            if self.host_mode is 6:
                sw_v6_ip = '1000::%d:1' % host_id
            # Ensure each host's interface name is unique, or else
            # mininet cannot shutdown gracefully

            h.defaultIntf().rename('%s-eth0' % host_name)
            # static arp entries and default routes
            h.cmd('arp -i %s -s %s %s' % (h_iface.name, sw_ip, sw_iface.mac))
            h.cmd('ethtool --offload %s rx off tx off' % h_iface.name)
            h.cmd('ip route add %s dev %s' % (sw_ip, h_iface.name))
            if self.host_mode is 6:
                h.cmd('ip -6 route add %s dev %s' % (sw_v6_ip, h_iface.name))
            h.setDefaultRoute("via %s" % sw_ip)
            #if self.host_mode is 6:
            #    h.setDefaultRoute("via %s" % sw_v6_ip)


    def do_net_cli(self):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")
        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial runtime configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        if self.switch_json:
            print('To inspect or change the switch configuration, connect to')
            print('its CLI from your host operating system using this command:')
            print('  simple_switch_CLI --thrift-port <switch thrift port>')
            print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' %  self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')
        if 'grpc' in self.bmv2_exe:
            print('To view the P4Runtime requests sent to the switch, check the')
            print('corresponding txt file in %s:' % self.log_dir)
            print(' for example run:  cat %s/s1-p4runtime-requests.txt' % self.log_dir)
            print('')
        
        
        for s in self.net.switches:
            if(s.name == 's1'):
                s.cmd('ifconfig s1-eth3 192.168.0.5 netmask 255.255.255.0 up')
                print("Configured Switch's IP Address")
        for h in self.net.hosts:
            if (h.name == 'h5'):
                h.cmd('ifconfig h5-eth0 192.168.0.100 netmask 255.255.255.0 up')
                h.cmd('h5 ifconfig h5-eth0 hw ether 00:00:00:00:01:05')
                print("Configured Controller's IP and MAC Addresses")
        for h in self.net.hosts:
            if (h.name == 'h1'):
                h.cmd('arp -s 10.0.1.2 00:00:00:00:01:02')
                print("Configured Traffic Generator's IP and MAC Addresses")
            if (h.name == 'h2'):
                h.cmd('arp -s 10.0.1.1 00:00:00:00:01:01')
        CLI(self.net)
        """
        
        s1_cmd = 's1 ./start_switch_cpu.sh '
        s1_cmd += str(self.port) + ' '
        s1_cmd += str(self.eviction_threshold) + ' '
        s1_cmd += str(self.cache_size) + ' '
        s1_cmd += str(self.random_rules_num) + ' '
        s1_cmd += str(self.read_counter_interval) + ' &'

        h1_cmd = 'python tg.py'

        h5_cmd = 'h5 ./start_p4_controller.sh '
        h5_cmd += str(self.threshold) + ' '
        h5_cmd += str(self.cache_size) + ' '
        h5_cmd += str(self.random_rules_num) + ' '
        h5_cmd += str(self.run_time) + ' '
        h5_cmd += str(self.port) + ' &'
        
        filename = "cli_cmds.sh"

        with open(filename,'w') as filehandle:
            filehandle.write(s1_cmd)
            filehandle.write('\n')
            #filehandle.write(h1_cmd)
            #filehandle.write('\n')
            filehandle.write(h5_cmd)
            filehandle.write('\n')

        print("Script file created")

        
        my_cli = CLI(self.net,script='cli_cmds.sh')
        print("Executed Commands")
        for h in self.net.hosts:
            if (h.name == 'h1'):
                h.sendCmd(h1_cmd)
                print("Started Traffic Generator")
                sleep(1)
        """
        """
        sleep(self.run_time + 15)
        for s in self.net.switches:
            if(s.name == 's1'):
                s.terminate()
                sleep(1)
                print("Killed Switch CPU Program")
        for h in self.net.hosts:
            if (h.name == 'h5'):
                h.terminate()
                sleep(1)
                print("Killed Controller Program")
        for h in self.net.hosts:
            if (h.name == 'h1'):
                h.terminate()
                sleep(1)
                print("Killed Traffic Generator")
        print("Killed all hosts and switches")
        
        
        for s in self.net.switches:
            if(s.name == 's1'):

                s.cmd(s1_cmd)
                print("Started Switch CPU Program")
                sleep(2)
        """
        """
        for h in self.net.hosts:
            if (h.name == 'h1'):
                h.sendCmd(h1_cmd)
                print("Started Traffic Generator")
                sleep(1)
        for h in self.net.hosts:
            if (h.name == 'h5'):
                h.sendCmd(h5_cmd)
                print("Started Controller Program")
                sleep(5)
        """
        """

        #CLI(self.net)
        
        sleep(self.run_time + 15)
        #self.net.stop()
        
        for s in self.net.switches:
            if(s.name == 's1'):
                s.terminate()
                sleep(1)
                print("Killed Switch CPU Program")
        for h in self.net.hosts:
            if (h.name == 'h5'):
                h.terminate()
                sleep(1)
                print("Killed Controller Program")
        for h in self.net.hosts:
            if (h.name == 'h1'):
                h.terminate()
                sleep(1)
                print("Killed Traffic Generator")
        """
        
        

def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                                type=str, required=False, default='simple_switch')
    parser.add_argument('-m', '--host_mode', help='Mode of Host, IPv4(4) or IPv6(6).',
                                type=int, required=False, default=4)
    

    parser.add_argument('-th', '--threshold', help='Packet Miss Threshold',
                                type=int, required=False, default=100)
    parser.add_argument('-cs', '--cache_size', help='Switchs Cache Size',
                                type=int, required=False, default=64)
    parser.add_argument('-rrn', '--random_rules_num', help='Random number of rules sample at Switchs CPU',
                                type=int, required=False, default=16)
    parser.add_argument('-rt', '--run_time', help='Simulation Time',
                                type=int, required=False, default=5)
    parser.add_argument('-pt', '--port', help='Socket Ports',
                                type=int, required=False, default=50001)
    parser.add_argument('-et', '--eviction_threshold', help='Above this threshold delete rules',
                                type=int, required=False, default=48)
    parser.add_argument('-rci', '--read_counter_interval', help='time interval to sample counters from cache',
                                type=float, required=False, default=1)

    return parser.parse_args()


if __name__ == '__main__':
    # from mininet.log import setLogLevel
    # setLogLevel("info")
    #os.system("sudo python3 TrafficGenerator.py")

    args = get_args()
    exercise = ExerciseRunner(args.topo, args.log_dir, args.pcap_dir,
                              args.switch_json,
                              args.behavioral_exe, 
                              args.quiet,
                              args.host_mode,
                              args.threshold,
                              args.cache_size,
                              args.random_rules_num,
                              args.run_time,
                              args.port,
                              args.eviction_threshold,
                              args.read_counter_interval)

    exercise.run_exercise()


