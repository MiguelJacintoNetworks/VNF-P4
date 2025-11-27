#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
const bit<16> TYPE_MSLP = 0x88B5;

// HEADERS

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header mslp_t {
    bit<16> etherType;
}

header label_t {
    bit<16> label;
    bit<8>  bos;
}

struct metadata {
    macAddr_t nextHopMac;
}

struct headers {
    ethernet_t ethernet;
    mslp_t     mslp;
    label_t[3] labels;
}

// PARSER

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
            TYPE_MSLP: parse_mslp;
            default:   accept;
        }
    }

    state parse_mslp {
        packet.extract(hdr.mslp);
        transition parse_labels;
    }

    state parse_labels {
        packet.extract(hdr.labels.next);
        transition select(hdr.labels.last.bos) {
            0x00: parse_labels;
            0x01: accept;
        }
    }
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forwardTunnel(bit<9> egressPort, macAddr_t nextHopMac) {
        standard_metadata.egress_spec = egressPort;
        meta.nextHopMac               = nextHopMac;
    }

    table labelLookup {
        key = {
            hdr.labels[0].label : exact;
        }
        actions = {
            forwardTunnel;
            drop;
        }
        size           = 16;
        default_action = drop;
    }

    action rewriteMacs(macAddr_t srcMac) {
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = meta.nextHopMac;
    }

    table internalMacLookup {
        key = {
            standard_metadata.egress_spec : exact;
        }
        actions = {
            rewriteMacs;
            drop;
        }
        size           = 16;
        default_action = drop;
    }

    apply {
        if (hdr.mslp.isValid() && hdr.labels[0].isValid()) {
            if (labelLookup.apply().hit) {
                internalMacLookup.apply();
            }
        } else {
            drop();
        }
    }
}

// EGRESS PROCESSING

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action popLabel() {
        hdr.labels.pop_front(1);
    }

    apply {
        if (hdr.mslp.isValid() && hdr.labels[0].isValid()) {
            popLabel();
        }
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mslp);
        packet.emit(hdr.labels);
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