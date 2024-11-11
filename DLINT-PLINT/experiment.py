#!/usr/bin/env python3
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
import argparse
import json
import os, sys
import subprocess
from time import sleep
from datetime import datetime
import random

hom=os.getcwd()[:os.getcwd().index('/', 6)]
#print(hom+'/tutorials/utils')
sys.path.append(hom+'/tutorials/utils')
#print(sys.path)
import p4runtime_lib.simple_controller
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.topo import Topo
from p4_mininet import P4Host, P4Switch
from p4runtime_switch import P4RuntimeSwitch


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
                print("%s -> gRPC port: %d" % (self.name, self.grpc_port))

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
                print("%s -> Thrift port: %d" % (self.name, self.thrift_port))

        return ConfiguredP4Switch


class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
    """
    def __init__(self, hosts, switches, links, log_dir, bmv2_exe, pcap_dir, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []

        # assumes host always comes first for host<-->switch links
        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)
            else:
                switch_links.append(link)

        for sw, params in switches.items():
            if "program" in params:
                switchClass = configureP4Switch(
                        sw_path=bmv2_exe,
                        json_path=params["program"],
                        log_console=True,
                        pcap_dump=pcap_dir)
            else:
                # add default switch
                switchClass = None
            self.addSwitch(sw, log_file="%s/%s.log" %(log_dir, sw), cls=switchClass)

        for link in host_links:
            host_name = link['node1']
            sw_name, sw_port = self.parse_switch_node(link['node2'])
            host_ip = hosts[host_name]['ip']
            host_mac = hosts[host_name]['mac']
            self.addHost(host_name, ip=host_ip, mac=host_mac)
            self.addLink(host_name, sw_name,
                         delay=link['latency'], bw=link['bandwidth'],
                         port2=sw_port)

        for link in switch_links:
            sw1_name, sw1_port = self.parse_switch_node(link['node1'])
            sw2_name, sw2_port = self.parse_switch_node(link['node2'])
            self.addLink(sw1_name, sw2_name,
                        port1=sw1_port, port2=sw2_port,
                        delay=link['latency'], bw=link['bandwidth'])


    def parse_switch_node(self, node):
        assert(len(node.split('-')) == 2)
        sw_name, sw_port = node.split('-')
        try:
            sw_port = int(sw_port[1:])
        except:
            raise Exception('Invalid switch node in topology file: {}'.format(node))
        return sw_name, sw_port


class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages

            hosts    : dict<string, dict> // mininet host names and their associated properties
            switches : dict<string, dict> // mininet switch names and their associated properties
            links    : list<dict>         // list of mininet link properties

            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary

            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance

    """
    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def format_latency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, str):
            return l
        else:
            return str(l) + "ms"


    def __init__(self, topo_file, log_dir, pcap_dir,
                       switch_json, bmv2_exe='simple_switch', quiet=False):
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
                link_dict['latency'] = self.format_latency(link[2])
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

        defaultSwitchClass = configureP4Switch(
                                sw_path=self.bmv2_exe,
                                json_path=self.switch_json,
                                log_console=True,
                                pcap_dump=self.pcap_dir)

        self.topo = ExerciseTopo(self.hosts, self.switches, self.links, self.log_dir, self.bmv2_exe, self.pcap_dir)

        self.net = Mininet(topo = self.topo,
                      link = TCLink,
                      host = P4Host,
                      switch = defaultSwitchClass,
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
                proto_dump_fpath=outfile,
                runtime_json=runtime_json
            )

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
        for sw_name, sw_dict in self.switches.items():
            if 'cli_input' in sw_dict:
                self.program_switch_cli(sw_name, sw_dict)
            if 'runtime_json' in sw_dict:
                self.program_switch_p4runtime(sw_name, sw_dict)

    def program_hosts(self):
        """ Execute any commands provided in the topology.json file on each Mininet host
        """
        for host_name, host_info in list(self.hosts.items()):
            h = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)


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

        print('-------------Launching Experiment------------------')

        
        #Get hosts
        host = [self.net.get('h01')]
        for i in range(1,28):
            host.append(self.net.get('h'+f'{i:02}'))
        
        hname=os.uname()[1]
        

        os.system("killall ITGRecv; killall ITGSend")
        sleep(1)


        #BTN: Start traffic receiver      
        host[12].cmdPrint('ITGRecv &')
        host[3].cmdPrint('ITGRecv &')
        host[17].cmdPrint('ITGRecv &')
        host[9].cmdPrint('ITGRecv &')
        

        sleep(1)
        #os.system('wireshark &')
        #input('Press key to continue')
        
      
        #BTN: Start 40 flows per path TCP traffic
        #host[1].cmdPrint('ITGSend s1.itg &')   
        #host[21].cmdPrint('ITGSend s21.itg &') 
        #host[8].cmdPrint('ITGSend s8.itg &') 
        #host[18].cmdPrint('ITGSend s18.itg &') 
        
        
        #BTN:1 flow (for testing)
        host[1].cmdPrint('ITGSend -a 10.0.1.12 -T TCP -rp 10074 -C 10 -c 100 &')
        

        print("Running for 60 seconds "+passString)

        #CLI(self.net)

        #In case of path a update (PU)
        if (performPU=='1'): print("Path Update in "+str(ran))
        
        sleep(ran) #Wait until path update time 
        h12pu=""
        h03pu=""
        h17pu=""
        h09pu=""
        
        if (performPU=='1'):
            print('Changing paths')

           
            #BTN: Perform path update (register time)           
            h12pu=str(datetime.now().time())
            os.system('printf \"table_modify MyIngress.ipv4_lpm MyIngress.ipv4_forward 11 08:00:00:00:01:12 3\" | simple_switch_CLI --thrift-port 9097') #Path Update for node s8  
            h03pu=str(datetime.now().time())
            os.system('printf \"table_modify MyIngress.ipv4_lpm MyIngress.ipv4_forward 2 08:00:00:00:01:03 4\" | simple_switch_CLI --thrift-port 9115') #Path Update for node s26  
            h17pu=str(datetime.now().time())
            os.system('printf \"table_modify MyIngress.ipv4_lpm MyIngress.ipv4_forward 16 08:00:00:00:01:17 8\" | simple_switch_CLI --thrift-port 9108') #Path Update for node s19  
            h09pu=str(datetime.now().time())
            os.system('printf \"table_modify MyIngress.ipv4_lpm MyIngress.ipv4_forward 8 08:00:00:00:01:09 7\" | simple_switch_CLI --thrift-port 9108') #Path Update for node s19  
            #print(datetime.now().time())
            

        sleep(60-ran+3) #After path update
        os.system("killall ITGRecv; killall ITGSend") #Stop traffic
        
        
        print('-------------End of Experiment------------------')

        #BTN: Parse output
        os.system('echo "---s12---" | tee experiment.out')
        os.system('python3 parsedump.py s12-eth2 10.0.1.1 10.0.1.12 2 '+values+' '+h12pu+' | tee -a experiment.out')
        os.system('echo "---s3---" | tee -a experiment.out')
        os.system('python3 parsedump.py s3-eth3 10.0.1.21 10.0.1.3 2 '+values+' '+h03pu+' | tee -a experiment.out')
        os.system('echo "---s17---" | tee -a experiment.out')
        os.system('python3 parsedump.py s17-eth3 10.0.1.8 10.0.1.17 2 '+values+' '+h17pu+' | tee -a experiment.out')
        os.system('echo "---s9---" | tee -a experiment.out')
        os.system('python3 parsedump.py s9-eth4 10.0.1.18 10.0.1.9 2 '+values+' '+h09pu+' | tee -a experiment.out')
        
       
        print('-'*20+'\n') #Print dash line        
       
        #Read and sum Total values of Accurate and Inaccurate paths and found vs lost switch IDs
        
        outp = open('experiment.out','r')

        acc=0
        inacc=0
        totfound=0
        totlost=0
        totAlt=0
        #totAltUn=0
        totFlows=0
        totLReset=0
        totPU=0
        totPacks=0
        totINT=0
        totValINT=0
        totDupl=0
        totExtraINT=0
        totRedunt=0
        timeLapses=[]

        lin=outp.readline()
        while lin:
            if (lin.find('Accurate= ')>-1):
                acc+=int(lin[lin.find('= ')+2:])
            else:
                if lin.find('Inaccurate= ')>-1:
                    inacc+=int(lin[lin.find('= ')+2:])
                else:
                    if (lin.find('Total foundLabels= ')>-1):
                        totfound+=int(lin[lin.find('= ')+2:]) 
                    else:
                        if (lin.find('Total lostLabels= ')>-1):
                            totlost+=int(lin[lin.find('= ')+2:])
                        else:
                            if (lin.find('Total Lost Reset= ')>-1):
                                totLReset+=int(lin[lin.find('= ')+2:])
                            else:
                                if (lin.find('Path Update detected by= ')>-1):
                                    thisAlt=int(lin[lin.find('= ')+2:])
                                    totAlt+=thisAlt
                                else:
                                    if (lin.find('Average PU time lapse= ')>-1):
                                        totPU+=float(lin[lin.find('= ')+2:])*thisAlt
                                    else:
                                        if (lin.find('TimeLapse= ')>-1):
                                            timeLapses.append(int(lin[lin.find('= ')+2:]))
                                        else:
                                            if (lin.find('Total flows= ')>-1):
                                                totFlows+=int(float(lin[lin.find('= ')+2:]))
                                            else:
                                                if (lin.find('Total packets= ')>-1):
                                                    totPacks+=int(lin[lin.find('= ')+2:])
                                                else:
                                                    if (lin.find('Total INT packets= ')>-1):
                                                        totINT+=int(lin[lin.find('= ')+2:])
                                                    else:
                                                        if (lin.find('Valuable INT packets= ')>-1):
                                                            totValINT+=int(lin[lin.find('= ')+2:])
                                                        else:
                                                            if (lin.find('Total Duplicates= ')>-1):
                                                                totDupl+=int(lin[lin.find('= ')+2:])
                                                            else:
                                                                if (lin.find('Extra INT packets= ')>-1):
                                                                    totExtraINT+=int(lin[lin.find('= ')+2:])
                                                                else:
                                                                    if (lin.find('Total Redundant= ')>-1):
                                                                        totRedunt+=int(lin[lin.find('= ')+2:])
                                                                
                
            lin=outp.readline()

        if len(timeLapses)!=0 :
            avg=round(sum(timeLapses)/len(timeLapses))
        else:
            avg=0
        #timeLapsesNonExcess=[x for x in timeLapses if x<2000000]


        totAvgPU=0
        if totAlt!=0: totAvgPU=round(totPU/totAlt)

        timeLapses.sort() #Sort to calc median

        #Check for extreme values
        cutoff=0
        for i in range(1,totAlt//10+1):    
            if timeLapses[totAlt-i]<1000000: break  
            thisavg=sum(timeLapses[:totAlt-i])/(totAlt-i)
            prevavg=sum(timeLapses[:totAlt-i+1])/(totAlt-i+1)
            if thisavg*2<prevavg: cutoff=i

        os.system('echo '+str(timeLapses)+'>> pupdates.out') #save all values for reference
        if len(timeLapses)>0:
            if len(timeLapses)%2==0:
                median=timeLapses[len(timeLapses)//2-1]+timeLapses[len(timeLapses)//2]
            else:
                median=timeLapses[len(timeLapses)//2]
        else:
            median=0
        if (totAlt-cutoff>0):
            nonex=round(sum(timeLapses[:totAlt-cutoff])/(totAlt-cutoff))
        else:
            nonex=0
        print('Total Acc paths found = ', acc)
        print('Total Inacc paths found = ', inacc)
        print('Total Found swIDs = ', totfound)
        print('Total Lost SwIDs = ', totlost)
        print('Total Lost Reset = ', totLReset)        
        print('Total path updates detected = ', totAlt)
        print('Total Average PU time lapse= ', avg,'Median= ',median, 'Non-Ex= ', nonex,'Non-Ex values= ',totAlt-cutoff,'Ex=',cutoff)
        print('Total Flows = ', totFlows)
        print('Total Pakcets = ', totPacks)
        print('Total INT Pakcets = ', totINT)        
        print('Total Extra INT Pakcets = ', totExtraINT)
        print('Total Valuable INT Pakcets = ', totValINT)
        print('Total duplicates = ', totDupl)
        print('Total Redundant = ', totRedunt)
        print('---------------------------------------')

        outp.close()
        

        

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
    parser.add_argument('-v', '--telemetry_values', help='Number of telemetry values per packet',
                                type=str, required=False, default='1')
    parser.add_argument('-s', '--pass_string', help='Percent of jobs done',
                                type=str, required=False, default='')
    parser.add_argument('-f', '--bf_size', help='Bloom Filter size',
                                type=str, required=False, default='none')
    parser.add_argument('-u', '--path_update', help='Path Update (0/1)',
                                type=int, required=False, default=0)
    parser.add_argument('-r', '--timeOfPU', help='Time when path update takes place (10-50)',
                                type=int, required=False, default=0)
    return parser.parse_args()


if __name__ == '__main__':

    args = get_args()
    values = str(args.telemetry_values)
    passString = str(args.pass_string)
    bf = str(args.bf_size)
    performPU = str(args.path_update)
    ran = args.timeOfPU
    print("Telemetry method and values per packet: "+values)
    exercise = ExerciseRunner(args.topo, args.log_dir, args.pcap_dir,
                              args.switch_json, args.behavioral_exe, args.quiet)

    exercise.run_exercise()
