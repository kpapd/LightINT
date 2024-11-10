#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os,sys
if (os.uname()[1]=='kpapad-OptiPlex-380'):
    sys.path.insert(1, '/home/kpapad/p4dev-python-venv/lib/python3.10/site-packages')
import argparse, grpc
from time import sleep
from scapy.all import *
from threading import Thread
from queue import Queue

# set our lib path
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
     #   '/home/kpapad/p4-researching/utils'))
        './utils/'))

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

# And then we import
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

installedRules = {}             #Database of pushed Rules to swtiches
listOfFlows = {}
s=[]                            #List of all switches
withholdDigest = Queue()
prevHandle = ''
shtDown=False

#List of Forwarding ports
ports=[[1,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,2,2,2,2,2,2,2,2,2,2,2],
[2,1,3,3,3,3,3,3,3,3,3,3,3,3,3,3,2,2,2,2,2,2,2,2,2,2,2],
[2,2,1,3,3,3,3,3,3,3,3,3,3,3,3,3,2,2,2,2,3,2,2,2,2,2,2],
[2,2,2,1,4,4,4,4,4,4,4,4,3,4,4,4,4,3,3,3,4,3,3,3,3,3,3],
[2,2,2,2,1,5,4,4,4,4,4,5,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
[2,2,2,2,2,1,3,3,3,3,3,3,2,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
[3,3,3,3,3,2,1,4,4,4,4,4,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4],
[2,2,2,2,2,2,2,1,4,4,4,4,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
[2,2,2,2,2,2,2,2,1,4,4,4,2,3,3,3,3,4,3,3,3,3,3,3,3,3,3],
[2,2,2,2,2,2,2,2,2,1,4,4,4,4,3,4,4,4,4,4,4,4,4,4,4,4,4],
[2,2,2,2,2,2,2,2,2,2,1,3,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3],
[2,2,2,2,2,2,2,2,2,2,2,1,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3],
[2,2,2,2,2,2,2,2,2,2,3,3,1,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
[3,3,3,3,3,3,4,4,5,6,6,5,2,1,2,7,2,2,2,2,7,2,2,2,2,7,7],
[2,2,2,2,3,3,3,3,3,3,3,3,2,3,1,2,2,2,2,2,2,2,2,2,2,2,2],
[2,2,2,2,2,2,2,2,3,2,3,3,2,2,2,1,4,5,5,5,4,4,4,5,5,4,5],
[2,2,2,2,2,2,2,3,2,2,2,2,2,2,2,2,1,3,3,3,3,3,3,3,3,3,3],
[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,2,2,2,2,2,2,2,2,2],
[4,4,3,3,3,3,3,2,8,2,2,2,3,2,2,2,6,5,1,6,6,8,8,8,8,8,8],
[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,2,2,1,3,3,3,3,3,3,3],
[2,2,3,2,2,2,2,2,2,2,2,2,2,2,2,2,3,2,2,2,1,3,3,3,3,3,3],
[3,3,4,3,3,3,3,3,4,3,3,3,3,3,3,3,4,4,4,4,3,1,4,4,4,4,4],
[2,2,4,2,2,2,2,3,4,4,4,4,2,4,4,4,4,2,4,3,3,3,1,4,4,4,4],
[2,2,2,2,2,2,2,2,3,4,4,4,2,2,2,4,3,2,2,2,2,3,3,1,3,3,3],
[2,2,2,2,4,4,4,4,4,4,4,4,4,4,4,4,5,3,2,2,3,3,3,3,1,5,3],
[4,4,3,4,3,3,3,2,3,3,3,3,4,3,3,3,3,4,4,4,2,2,2,4,4,1,2],
[3,3,2,3,3,3,3,4,3,3,3,3,3,3,3,3,2,4,3,3,4,4,4,3,3,2,1]]


def printGrpcError(e):
    print("gRPC Error: ", e.details(),end="")
    status_code = e.code()
    print("({})".format(status_code.name),end="")
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print("[{}:{}]".format(traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def SendDigestEntry(p4info_helper, sw, digest_name=None):
    digest_entry = p4info_helper.buildDigestEntry(digest_name=digest_name)
    sw.WriteDigestEntry(digest_entry)
    #print("Sent DigestEntry via P4Runtime in switch: "+sw.name)

def byte_pbyte(data):
    # check if there are multiple bytes
    if len(str(data)) > 1:
        # make list all bytes given
        msg = list(data)
        # mark which item is being converted
        s = 0
        for u in msg:
            # convert byte to ascii, then encode ascii to get byte number
            u = str(u).encode("hex")
            # make byte printable by canceling \x
            u = "\\x"+u
            # apply coverted byte to byte list
            msg[s] = u
            s = s + 1
        msg = "".join(msg)
    else:
        msg = data
        # convert byte to ascii, then encode ascii to get byte number
        msg = str(msg).encode("hex")
        # make byte printable by canceling \x
        msg = "\\x"+msg
    # return printable byte
    return msg

def prettify(mac_string):
    #print("mac_string=",mac_string)
    #print([b for b in mac_string])
    mac_end=str(mac_string)[2:-1].replace('\\x','')
    mac='0'*(12-len(mac_end))+mac_end
    macf=':'.join(mac[i:i+2] for i in range(0,len(mac),2))    
    return macf     #':'.join('%02x' % ord(str(b)) for b in mac_string)

def prettyIP(z):
    #return "".join([int.from_bytes(x, "big") for x in IPstring.split('\\')])
    return str(z[0])+'.'+str(z[1])+'.'+str(z[2])+'.'+str(z[3])
    
#Get a new pos to send to switch for a new rule
def getNewPos(switch):
    max=0
    for sw5t,pos in installedRules.items():        
        if str(switch.name)==sw5t.split()[0] and pos>max:
            max=pos
    return max+1

#Write forwarding rules to switch
def writeRuleFd(p4info_helper, switch, dstIP, dstMac, egressPort):
    #Writes a rule in a switch table
       
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dstIP,32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dstMac,
            "port": egressPort
        })
    switch.WriteTableEntry(table_entry)
    
#Initial switch configurations
def initSwitches(p4info_helper, bmv2_file_path):

    try:
        #Define switch handles
        for i in range(1,28):
            s.append(p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s'+str(i),
                address='127.0.0.1:500'+str(50+i),
                device_id=i-1,
                proto_dump_file="logs/s"+str(i)+"-runtime-requests.txt"))
        s.insert(0,s[0])
        #print(s[1].name,s[1].address,s[1].device_id,s[1].proto_dump_file,type(s[1].device_id))

        #Initiate tables, upload p4 program, initialize identify table
        for i in range(1,28):
            s[i].MasterArbitrationUpdate()
            s[i].SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
            table_entry = p4info_helper.buildTableEntry(
                    table_name="MyIngress.identify",
                    action_name="MyIngress.getID",
                    action_params= {
                     "myswid": i,
                     "hostports": 1
                   })
            s[i].WriteTableEntry(table_entry)
        print("Installed P4 Program using SetForardingPipelineConfig on s1-s27")
        #input('Press key to continue')


        
        #Forwarding Rules
        for i in range(1,28):
            for j in range(1,28):
                writeRuleFd(p4info_helper, switch=s[i], dstIP="10.0.1."+str(j), dstMac="08:00:00:00:01:"+str(j).zfill(2), egressPort=ports[i-1][j-1])
        print("Installed Forwarding Rules in s1-s27")

        for i in range(1,28):
            SendDigestEntry(p4info_helper, sw=s[i], digest_name="digest_t")
        print("Installed Digest Entry to s1-s27")
        #writeRuleFd(p4info_helper, switch=s[1], dstIP="10.0.1.2", dstMac="08:00:00:00:01:02", egressPort=2)
        
        #writeRuleFd(p4info_helper, switch=s[2], dstIP="10.0.1.1", dstMac="08:00:00:00:01:01", egressPort=2)
        #writeRuleFd(p4info_helper, switch=s[2], dstIP="10.0.1.2", dstMac="08:00:00:00:01:02", egressPort=1)    
    except KeyboardInterrupt:
        #using ctrl + c to exit
        print("Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)
        print(f"Received unknown RPC error: code={e.code()} message={e.details()}")

    
#Write new intPos rule to set a position on the switches' array for a specific 5-tuple
def writeRule(p4info_helper, switch, srcIP, dstIP, srcPort, dstPort, pos):
    #Writes or modifiesa rule in a switch table    
    
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.intPos",
        match_fields={
            "hdr.ipv4.srcAddr": srcIP,
            "hdr.ipv4.dstAddr": dstIP,
            "hdr.tcp.srcPort": srcPort,
            "hdr.tcp.dstPort": dstPort
        },
        action_name="MyIngress.getPos",
        action_params={
            "arrayPos": pos, #.to_bytes(2,'big')
        })
    
    switch.WriteTableEntry(table_entry)

#Handle digest incoming digest messages
def handleDigest(p4info_helper, switch, srcIP, dstIP, srcPort, dstPort):
    global totalDigestMsgs    
    global totEntries, totFlows

    lastDstIP=int(dstIP[dstIP.rfind('.')+1:]) #Find the last part of the IP
    lastSrcIP=int(srcIP[srcIP.rfind('.')+1:])

    #Smaller IP first
    if lastDstIP<lastSrcIP:
        sw5t = switch.name+' '+dstIP+' '+srcIP+' '+str(dstPort)+' '+str(srcPort)   #Key for installedRules dictionary
        reverse = True
    else:
        sw5t = switch.name+' '+srcIP+' '+dstIP+' '+str(srcPort)+' '+str(dstPort)
        reverse = False

    if sw5t not in installedRules.keys():
        pos=getNewPos(switch)
        installedRules[sw5t]=pos
        totEntries+=1

        if reverse==True:
            writeRule(p4info_helper, switch, dstIP, srcIP, dstPort, srcPort, pos)
        else:
            writeRule(p4info_helper, switch, srcIP, dstIP, srcPort, dstPort, pos)        
    else:
        if switch.name=="s1":
            print("    missed: ", switch.name+' '+dstIP+' '+srcIP+' '+str(dstPort)+' '+str(srcPort))

        

#THREAD funcion (one for each switch) to listen for digests
def readDigest(switch, q, shtDn):
    global totalDigestMsgs
    global digestIDs

    digestList = []
    failList = {}

    print('\033[0;32m'+ switch.name[1:]+'\033[0;37m,', end="", flush=True)
    killThread=False
    while killThread==False:
        try:
            digestsObj = switch.DigestList()
            for digests in digestsObj:                
                if str(digests).find('data')>-1 and digests.digest.data[0] not in digestList:
                    digest = digests.digest         
                    digest_message_list = digest.data   
                    swID=int(digests.digest.data[0].struct.members[0].bitstring.hex(),16)
                    srcIP=prettyIP(digests.digest.data[0].struct.members[1].bitstring)
                    dstIP=prettyIP(digests.digest.data[0].struct.members[2].bitstring)
                    srcPort=int(digests.digest.data[0].struct.members[3].bitstring.hex(),16)
                    dstPort=int(digests.digest.data[0].struct.members[4].bitstring.hex(),16)
                    if digests.digest.list_id>digestIDs[swID-1][-1]+1:
                        print()
                        print('lost digest id in switch: ',swID,digestIDs[swID-1][-1],digests.digest.list_id)
                    digestIDs[swID-1].append(digests.digest.list_id)
                
                    #print('readDigest',swID,srcIP,dstIP,srcPort,dstPort)
                    
                    q.put([swID, srcIP, dstIP, srcPort, dstPort])
                    totalDigestMsgs+=1
                    digestList.append(digests.digest.data[0])
        except KeyboardInterrupt:
            #using ctrl + c to exit
            print("Shutting down.")
            killThread=True
        except grpc.RpcError as e:
            print('\033[0;31m'+ switch.name[1:]+"\033[0;37m,", end="", flush=True)
            #print()
            killThread=True     
            shtDn.set()
            #os._exit(0)

def main(p4info_file_path, bmv2_file_path):
    
    p4info_helper = p4runtime_lib.helper.P4InfoHelper('./build/base.p4.p4info.txt')
    shtDown = threading.Event()

    try:            

        initSwitches(p4info_helper, bmv2_file_path)

        digestMessages = Queue()
        switchThreads=[]
        totalDigestMsgs = 0
        threadsAlive = 0


        print('Threads:', end="", flush=True)
        for i in range(1,28):
            switchThreads.append(Thread(target=readDigest, args=(s[i], digestMessages, shtDown)))
            switchThreads[i-1].deamon = True
            switchThreads[i-1].start()
            threadsAlive+=1
        print(' ')

       

        # Using stream channel to receive DigestList
        while not shtDown.is_set():
            if not digestMessages.empty():
                [swID, srcIP, dstIP, srcPort, dstPort] = digestMessages.get(block=True,timeout=5)
                handleDigest(p4info_helper, s[swID], srcIP, dstIP, srcPort, dstPort) 

        #Caclulate statistics
        flowRulesPerSwitch = {}

        for i in range(1,28):
            flowRulesPerSwitch['s'+str(i)]=0
        totalFlowRules=0
        flows = []
        totalFlows=0
        for item in installedRules:
            swName = item[:item.find(' ')]
            flow = item[item.find(' ')+1:]
            if flow not in flows:
                flows.append(flow)
            flowRulesPerSwitch[swName]+=1
            totalFlowRules+=1
        print("Total Flow Rules: ", totalFlowRules)
        print("Total Flows: ", len(flows))
        mult = open('multiExp.txt','a')
        mult.write('\t'+str(totalFlowRules)+'\n')
        mult.close()
        for sw in flowRulesPerSwitch.keys():
            #print(sw, flowRulesPerSwitch[sw])
            num=flowRulesPerSwitch[sw]
            if num%40!=0:
                print(sw,num)
        


    except grpc.RpcError as e:
        printGrpcError(e)
        print(f"Received unknown RPC error: code={e.code()} message={e.details()}")
        shtDown.set()
    except Empty:
        pass

    print("Terminated...")

    # Then close all the connections
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    """ Simple P4 Controller
        Args:
            p4info: Specify the p4info generated by P4 Program compilation (the format specified by PI, read by the controller)
            bmv2-json: Specify the json format generated by P4 Program compilation. There are different file formats depending on the backend
     """

    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    # Specified result which compile from P4 program
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
            type=str, action="store", required=False,
            default="./simple.p4info")
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
            type=str, action="store", required=False,
            default="./simple.json")
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: {}\nPlease compile the target P4 program first.".format(args.p4info))
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nPlease compile the target P4 program first.".format(args.bmv2_json))
        parser.exit(1)

    totalDigestMsgs = 0
    totEntries = 0
    threadsAlive = 0
    totFlows = 0
    digestIDs = [[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0],[0]]

    # Pass argument into main function
    main(args.p4info, args.bmv2_json)

