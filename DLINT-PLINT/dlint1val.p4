/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<5>  IPV4_OPTION_MRI = 31;

#define MAX_HOPS 9
#define BLOOM_FILTER_ENTRIES 3281


//Special Signals
#define INIT 0
#define RESET 255
//Bloom Filter States
#define AW_INIT 0
#define READY_INS 1
#define INSERTED 2
//switch_t length
#define PFALENGTH 1

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> switchID_t;
typedef bit<1> reset_t;
  
//typedef bit<32> qdepth_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
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
    switchID_t  swid;
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
    
    

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
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
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<2>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    bit<32> reg_pos_one; 
    bit<2> reg_val_one; 
    bit<2> reg_val_wr;
    bit<8> thisswid;
    bit<9> ports;


    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2){
       //Get register position
       hash(reg_pos_one, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action add_swtrace(switchID_t myswid, bit<9> hostports) {

        thisswid=myswid;
        ports=hostports;      
        
    }

    table identify {
        actions = { 
            add_swtrace; 
            NoAction; 
        }
        default_action = NoAction();      
    }
    
    apply {
    
        if (hdr.tcp.isValid()) {
            thisswid=0;
            ports=0;
            identify.apply();
            
            compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort); //Opposite direction
            bloom_filter_1.read(reg_val_one, reg_pos_one); 

            if (hdr.swtraces.isValid() && hdr.swtraces.swid==RESET && standard_metadata.egress_port==ports) { // If Reset comes and outputs to host
                bloom_filter_1.write(reg_pos_one, AW_INIT); // Set state of opposite direction to Awaiting Init
            } else if (reg_val_one == INSERTED && standard_metadata.ingress_port==ports) { // If opposite is in "Inserted SWID" state and comes from host then insert RESET
                hdr.swtraces.setValid();
                hdr.tcp.intflag=1;
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + PFALENGTH;
                hdr.swtraces.swid = RESET; // Insert Reset
                bloom_filter_1.write(reg_pos_one, AW_INIT); // Set state to Awaiting Init
            } else {
            
                compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
                bloom_filter_1.read(reg_val_one, reg_pos_one); //Read BF state

                if (hdr.swtraces.isValid() && hdr.swtraces.swid==INIT) { //If INIT is present
                    bloom_filter_1.write(reg_pos_one, READY_INS); // Set state to Ready to instert swID
                } else if (reg_val_one == READY_INS && !hdr.swtraces.isValid()) { // My turn to insert swID
                    hdr.swtraces.setValid();
                    hdr.tcp.intflag=1;
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + PFALENGTH;
                    hdr.swtraces.swid = thisswid; // Insert my swID
                    bloom_filter_1.write(reg_pos_one, INSERTED); // Set state to Inserted swID
                } else if (standard_metadata.ingress_port==ports && (reg_val_one==AW_INIT || hdr.tcp.syn==1)) { // If in Awaiting Init state and packet from host
                    hdr.swtraces.setValid();
                    hdr.tcp.intflag=1;
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + PFALENGTH;
                    hdr.swtraces.swid = INIT; // Insert INIT
                    bloom_filter_1.write(reg_pos_one, READY_INS); //Set state to Ready
                } else if (hdr.swtraces.isValid() && hdr.swtraces.swid!=RESET && hdr.swtraces.swid!=INIT && reg_val_one != READY_INS) { //Something has gone wrong - Reset
                    if (standard_metadata.egress_port==ports) {
                        bloom_filter_1.write(reg_pos_one, INSERTED); //Set state to Inserted swID 
                    } else {
                        bloom_filter_1.write(reg_pos_one, READY_INS); //Set state to Ready to insert
                    }
                } 
            }
            
                
            if (standard_metadata.egress_port==ports && hdr.swtraces.isValid()) { // If output to host then strip swid header
                hdr.tcp.intflag = 0; //Drop the intflag
                hdr.ipv4.totalLen = hdr.ipv4.totalLen - 1;
                hdr.swtraces.setInvalid();
                
            }
        }            
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
