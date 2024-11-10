/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<5>  IPV4_OPTION_MRI = 31;

#define CPU_PORT 255
#define MAX_HOPS 9
#define STATE_ARRAY_ENTRIES 400
#define HASH_TABLE_ENTRIES 89876
#define HASH_BIT_WIDTH 1


//Special Signals
#define INIT 204    //cc
#define RESET 255   //ff
#define BLANK 221   //dd
#define PREPARE 238 //ee
//Bloom Filter States
#define SET_UP 0
#define AW_INIT 1
#define READY_INS 2
#define INSERTED 3
//switch_t length
#define PFALENGTH 2

register<bit<2>>(STATE_ARRAY_ENTRIES) state_array;  
register<bit<HASH_BIT_WIDTH>>(HASH_TABLE_ENTRIES) hash_table;  
register<bit<8>>(1) idReg;
register<bit<9>>(1) portsReg;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
#typedef bit<48> macAddr_t;
#typedef bit<32> ip4Addr_t;
typedef bit<8> switchID_t;
typedef bit<1> reset_t;
  
//typedef bit<32> qdepth_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

/*header int_t {
    bit<16>  count;
}*/

header switch_t {    
    switchID_t  swid1;
    switchID_t  swid2;
    //qdepth_t    qdepth;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<1>  intflag;
    bit<3>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


/*
struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}
*/

// digest
struct digest_t {
    bit<8>  swID;
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
}

struct metadata {
    //ingress_metadata_t   ingress_metadata;
    //parser_metadata_t   parser_metadata;
}

struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;    
    switch_t swtraces;
    tcp_t tcp;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    
    /*
    state parse_ipv4 {
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol){
        TYPE_TCP: tcp;
        default: accept;
    }
    */

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.intflag){
            1: parse_swtrace;
            default: accept;
        }
    }

    state parse_swtrace {
        packet.extract(hdr.swtraces);
        transition accept;
    }

}




/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    

    bit<32> pos;        //Current Flow position in state_array
    bit<32> posRev;     //Reverse Flow position
    bit<32> array_pos;  //Pos of getPos
    bit<8> thisswid;
    bit<9> ports;
    bit<32> regPos;
    bit<8> rand;
    bit<32> reg_pos; 
    bit<HASH_BIT_WIDTH> reg_val; 
    

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action getID(switchID_t myswid, bit<9> hostports) {

        thisswid=myswid;
        ports=hostports;      
        
    }

    table identify {
        actions = { 
            getID; 
            NoAction; 
        }
        default_action = NoAction();      
    }

    
    

    action ipv4_forward(bit<48> dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    //---------------intPos table-------------------
    
    action getPos(bit<32> arrayPos) {
        array_pos=arrayPos;       
    }

    action sendDigest() {
        // Send digest        
        digest<digest_t>((bit<32>) 1024,
            { 
                    thisswid,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort               
            });
    }

    table intPos {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.srcPort: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            getPos;
            sendDigest;
            NoAction;
        }
        default_action = NoAction();
    }
    //---------------------------------------------

    action swapIPs() { //Swap IPs so that larger IP is first (src)
        bit<32> tmpIP;
        bit<16> tmpPort;

        tmpIP=hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr=hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr=tmpIP;
        tmpPort=hdr.tcp.srcPort;
        hdr.tcp.srcPort=hdr.tcp.dstPort;
        hdr.tcp.dstPort=tmpPort;
    }

    action compute_hashes(bit<32> ipAddr1, bit<32> ipAddr2, bit<16> port1, bit<16> port2){
       //Get register position
       hash(reg_pos, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)HASH_TABLE_ENTRIES);
    }
    
    apply {

        bool rev=false;        
        
        //Get my swID
        thisswid=0;
        ports=0;
        idReg.read(thisswid,regPos);
        portsReg.read(ports,regPos);  
        //If switch ID not specified then get value from identify table
        if (thisswid==0) {
            identify.apply();
            idReg.write((bit<32>)0,thisswid);
            portsReg.write((bit<32>)0,ports);
        }

        if (hdr.ipv4.isValid()) {            
            ipv4_lpm.apply(); 
            
            if (hdr.tcp.isValid() && hdr.tcp.srcPort!=9000 && hdr.tcp.dstPort!=9000) { //Control tcp flows not monitored
                //log_msg("hdr.swtraces.isValid = {}",{hdr.swtraces.isValid()});
                array_pos=0;
                pos=0;

                //Get INTpos position of current flow in state_array
                if (hdr.ipv4.dstAddr<hdr.ipv4.srcAddr) { //Flow rules stored with smaller IP first
                    //log_msg("src = {}, dst = {}", {hdr.ipv4.srcAddr,hdr.ipv4.dstAddr});
                    swapIPs();
                    rev=true;
                }
                intPos.apply();
                if (rev==true) { //Current Flow is in second seat of getPos
                    swapIPs(); //Swap back in place
                    pos=array_pos*2+1;
                    posRev=array_pos*2;
                } else { //Current Flow is in first seat of getPos
                    pos=array_pos*2;
                    posRev=array_pos*2+1;
                }
              
                if (array_pos!=0) { //Current flow has an entry in state_array
                    bit<2> back_state;
                    bit<2> frwd_state;

                    //----------------------INT label insertion---------------------------
                
                    state_array.read(back_state, posRev);
                    state_array.read(frwd_state, pos); 
                    /*
                    if (hdr.swtraces.isValid()) {
                        log_msg("IN swid = {},frwd_state = {}, back_state = {}, dstAddr = {}",{hdr.swtraces.swid,frwd_state,back_state, hdr.ipv4.dstAddr});
                    } else {
                        log_msg("IN NO swid,frwd_state = {}, back_state = {}, dstAddr = {}",{frwd_state,back_state, hdr.ipv4.dstAddr});
                    }   
                    //log_msg("frwd_state = {}, hdr.swtraces.isValid = {}, hdr.swtraces.swid = {}, hdr.ipv4.dstAddr = {}",{frwd_state, hdr.swtraces.isValid(), hdr.swtraces.swid, hdr.ipv4.dstAddr});
                    */

                    if (standard_metadata.ingress_port==ports && frwd_state==SET_UP) { //If in PREPARE phase
                        // IntPos table entry received-> forward PREPARE signal
                        hdr.swtraces.setValid();
                        hdr.tcp.intflag=1;
                        hdr.ipv4.totalLen = hdr.ipv4.totalLen + PFALENGTH;
                        hdr.swtraces.swid1 = PREPARE; // Insert PREPARE
                        hdr.swtraces.swid2 = BLANK; // Insert BLANK
                        state_array.write(pos, SET_UP);
                        frwd_state=SET_UP;
                    } else if (hdr.swtraces.isValid() && hdr.swtraces.swid1 == PREPARE) { // If PREPARE signal received
                       if (standard_metadata.egress_spec==ports) {
                            state_array.write(pos, INSERTED); // Trick flow to triger 
                            frwd_state=INSERTED;
                        } else {
                            state_array.write(pos, SET_UP);
                            frwd_state=SET_UP;
                        }
                    }

                    if (hdr.swtraces.isValid() && hdr.swtraces.swid1!=INIT && hdr.swtraces.swid1!=RESET && hdr.swtraces.swid1!=PREPARE && frwd_state!=READY_INS) { //Something has gone wrong - Reset
                        if (standard_metadata.egress_spec==ports) {
                            state_array.write(pos, INSERTED); //Set state to Inserted swID 
                        } else {
                            state_array.write(pos, READY_INS); //Set state to Ready to insert
                        }
                    }

                    if (hdr.swtraces.isValid() && hdr.swtraces.swid1==INIT) { //If INIT is present
                        if (frwd_state==SET_UP) { //If state was SET_UP zero BF
                            if (rev==false){ //Set hash_table back to 0 to avoid collisions!
                                compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
                            } else {
                                compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort);
                            }
                            hash_table.write(reg_pos,0);
                        } 
                        state_array.write(pos, READY_INS); // Set state to "Ready to instert swID"
                        frwd_state=READY_INS;
                    }

                    if (hdr.swtraces.isValid() && (hdr.swtraces.swid1==RESET || hdr.swtraces.swid2==RESET) && standard_metadata.egress_spec==ports) { // If Reset comes and outputs to host the set opposite direction to Awaiting INIT
                        state_array.write(posRev, AW_INIT); // Set state to Awaiting Init
                        back_state=AW_INIT;
                    }

                    if (standard_metadata.ingress_port==ports && (frwd_state == AW_INIT || hdr.tcp.syn==1)) { // If in Awaiting Init state and packet from host
                            hdr.swtraces.setValid();
                            hdr.tcp.intflag=1;
                            hdr.ipv4.totalLen = hdr.ipv4.totalLen + PFALENGTH;
                            hdr.swtraces.swid1 = INIT; // Insert INIT
                            hdr.swtraces.swid2 = thisswid;
                            state_array.write(pos, INSERTED); //Set state to Ready
                            frwd_state=INSERTED;
                    } 

                    if (back_state == INSERTED && standard_metadata.ingress_port==ports) { // If in "Inserted swID" state and packet comes from host
                        if (!hdr.swtraces.isValid()) { 
                            hdr.swtraces.setValid();
                            hdr.tcp.intflag=1;
                            hdr.ipv4.totalLen = hdr.ipv4.totalLen + PFALENGTH;
                            hdr.swtraces.swid1 = RESET; // Instert Reset
                            hdr.swtraces.swid2 = BLANK;
                        } else {
                            hdr.swtraces.swid2 = RESET; // INIT and swID has allready been inserted in previous if statement
                            state_array.write(pos, READY_INS); //Set state to Ready
                            frwd_state=READY_INS;
                        }
                        state_array.write(posRev, AW_INIT); // Set state to Awaiting Init
                        back_state=AW_INIT;
                    } 

                    if (frwd_state == READY_INS && ((!hdr.swtraces.isValid()) || hdr.swtraces.swid2 == BLANK )) { // My turn to insert swID                    
                        if (!hdr.swtraces.isValid()) {  
                            hdr.swtraces.setValid();
                            hdr.tcp.intflag=1;
                            hdr.ipv4.totalLen = hdr.ipv4.totalLen + PFALENGTH;
                            hdr.swtraces.swid1 = thisswid;
                            hdr.swtraces.swid2 = BLANK;    
                        } else {
                            hdr.swtraces.swid2 = thisswid; 
                        }                                 
                        state_array.write(pos, INSERTED); // Set state to Inserted swID
                        frwd_state=INSERTED;
                    }
                    
                } else { //No entry in state_array

                    //Check BF whether digest has been sent
                    if (rev==false){
                        compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
                    } else {
                        compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort);
                    }
                    hash_table.read(reg_val, reg_pos); //Read BF state
                    /*
                    if (rev==false){
                        log_msg("flow:{},{},{},{},{}",{hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort,reg_pos});
                    } else {
                        log_msg("flow:{},{},{},{},{}",{hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort,reg_pos});
                    }
                    */
                    //log_msg("reg_val={}",{reg_val});
                    if (reg_val==0) {
                        sendDigest();    
                        hash_table.write(reg_pos,reg_val+1);
                        //log_msg("digestSent:{}",{reg_pos});                    
                    }  

                    //If INT label exists and not prepared yet, drop INT label
                    if (hdr.swtraces.isValid() && hdr.swtraces.swid1==PREPARE) { //If PREPARE received but switch not prepared yet
                        //Strip INT header - block PREPARE signal
                        hdr.tcp.intflag = 0; //Drop the intflag
                        hdr.ipv4.totalLen = hdr.ipv4.totalLen - PFALENGTH;
                        hdr.swtraces.setInvalid();   
                    }
                }         

                if (standard_metadata.egress_spec==ports && hdr.swtraces.isValid()) { // If output to host then strip swid header
                    hdr.tcp.intflag = 0; //Drop the intflag
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen - PFALENGTH;
                    hdr.swtraces.setInvalid();                
                }
            }
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {    
    
    apply {
    
        
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              //hdr.ipv4.intflag,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        //packet.emit(hdr.ipv4_option);
        //packet.emit(hdr.int);
        packet.emit(hdr.tcp);
        packet.emit(hdr.swtraces);                       
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
