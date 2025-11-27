#include <core.p4>
#include <v1model.p4>

const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
typedef bit<48> macAddr_t;

// HEADERS

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_t {
    macAddr_t srcAddr;
    bit<16>   ingress_port;
}

struct metadata {
    @field_list(0)
    bit<9> ingress_port;
}

struct headers {
    ethernet_t eth;
    cpu_t      cpu;
}

// PARSER

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start { transition parse_ethernet; }
    state parse_ethernet { packet.extract(hdr.eth); transition accept; }
}

// CHECKSUM VERIFICATION

control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

// INGRESS PROCESSING

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action learnMac() {
        meta.ingress_port = standard_metadata.ingress_port;
        clone_preserving_field_list(CloneType.I2E, 100, 0);
    }

    table sMacLookup {
        key = { hdr.eth.srcAddr : exact; }
        actions = { learnMac; NoAction; }
        size = 256;
        default_action = learnMac;
    }

    action forward(bit<9> egressPort) {
        standard_metadata.egress_spec = egressPort;
    }

    table dMacLookup {
        key = { hdr.eth.dstAddr : exact; }
        actions = { forward; NoAction; }
        size = 256;
        default_action = NoAction;
    }

    apply {
        if (hdr.eth.isValid()) {
            sMacLookup.apply();
            if (!dMacLookup.apply().hit) {
                standard_metadata.mcast_grp = 1;
            }
        } else {
            mark_to_drop(standard_metadata);
        }
    }
}

// EGRESS PROCESSING

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if (standard_metadata.instance_type == 1) {
            hdr.cpu.setValid();
            hdr.cpu.srcAddr = hdr.eth.srcAddr;
            hdr.cpu.ingress_port = (bit<16>) meta.ingress_port;
            hdr.eth.etherType = L2_LEARN_ETHER_TYPE;
            truncate((bit<32>) 22);
        }
        if (standard_metadata.egress_port == standard_metadata.ingress_port) drop();
    }
}

// CHECKSUM COMPUTATION

control MyComputeChecksum(inout headers hdr,
                          inout metadata meta) {
    apply { }
}

// DEPARSER

control MyDeparser(packet_out packet,
                   in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.cpu);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;