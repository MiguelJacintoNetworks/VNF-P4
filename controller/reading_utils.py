import json
import os
import sys

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "../utils/",
    )
)

from p4runtime_lib.convert import decodeIPv4, decodeNum

def read_counter(helper, switch, counter_name, index):
    try:
        counter_id = helper.get_counters_id(counter_name)
        for response in switch.ReadCounters(counter_id, index):
            for entity in response.entities:
                if entity.HasField("counter_entry"):
                    counter_entry = entity.counter_entry
                    return counter_entry.data.packet_count
        return 0
    except Exception as e:
        print(f"ERROR READING COUNTER {counter_name} [{index}]: {e}")
        return 0
    
def print_table_rules(p4info_helper, sw):
    print(f"\nTABLE RULES FROM {sw.name}")

    if sw.HasP4ProgramInstalled():
        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table_name = p4info_helper.get_tables_name(entry.table_id)

                print(f"{table_name}: ", end = " ")

                for m in entry.match:
                    match_name = p4info_helper.get_match_field_name(
                        table_name, m.field_id
                    )
                    match_value = p4info_helper.get_match_field_value(m)
                    print(match_name, end = " ")
                    print(f"{match_value!r}", end = " ")

                action = entry.action.action
                action_name = p4info_helper.get_actions_name(action.action_id)
                print("->", action_name, end = " ")

                for p in action.params:
                    param_name = p4info_helper.get_action_param_name(
                        action_name, p.param_id
                    )
                    print(param_name, end = " ")
                    print(f"{p.value!r}", end = " ")

                print()

    print()

def parse_ipv4_lpm(entry, helper):
    enc_ip = helper.get_match_field_value(entry.match[0])
    ip = (decodeIPv4(enc_ip[0]), enc_ip[1])

    action_name = helper.get_actions_name(entry.action.action.action_id)
    params = {}

    if action_name == "MyIngress.forward":
        params = {
            "egressPort": decodeNum(entry.action.action.params[0].value),
            "nextHopMac": my_decode_mac(entry.action.action.params[1].value),
        }

    key = json.dumps({"hdr.ipv4.dstAddr": list(ip)})
    return key, action_name, params

def parse_label_lookup(entry, helper):
    lbl = decodeNum(helper.get_match_field_value(entry.match[0]))
    action_name = helper.get_actions_name(entry.action.action.action_id)

    params = {}
    if action_name == "MyIngress.forwardTunnel":
        params = {
            "egressPort": decodeNum(entry.action.action.params[0].value),
            "nextHopMac": my_decode_mac(entry.action.action.params[1].value),
        }

    key = json.dumps({"hdr.labels[0].label": convert_to_hex(lbl)})
    return key, action_name, params

def parse_internal_mac(entry, helper):
    port = decodeNum(helper.get_match_field_value(entry.match[0]))
    imac = my_decode_mac(entry.action.action.params[0].value)
    action_name = helper.get_actions_name(entry.action.action.action_id)

    params = {"srcMac": imac}
    key = json.dumps({"standard_metadata.egress_spec": port})
    return key, action_name, params

def parse_tunnel_lookup(entry, helper):
    tun = decodeNum(helper.get_match_field_value(entry.match[0]))
    lbl = decodeNum(entry.action.action.params[0].value)
    action_name = helper.get_actions_name(entry.action.action.action_id)

    params = {"labels": convert_to_hex(lbl)}
    key = json.dumps({"meta.tunnel": tun})
    return key, action_name, params

def parse_check_direction(entry, helper):
    ingress = decodeNum(helper.get_match_field_value(entry.match[0]))
    egress = decodeNum(helper.get_match_field_value(entry.match[1]))
    direction = decodeNum(entry.action.action.params[0].value)
    action_name = helper.get_actions_name(entry.action.action.action_id)

    params = {"dir": direction}
    key = json.dumps(
        {
            "meta.ingress_port": ingress,
            "standard_metadata.egress_spec": egress,
        }
    )
    return key, action_name, params

def parse_allowed_tcp(entry, helper):
    port = decodeNum(helper.get_match_field_value(entry.match[0]))
    action_name = helper.get_actions_name(entry.action.action.action_id)

    key = json.dumps({"hdr.tcp.dstPort": port})
    return key, action_name, {}
                                    
def parse_allowed_udp(entry, helper):
    port = decodeNum(helper.get_match_field_value(entry.match[0]))
    action_name = helper.get_actions_name(entry.action.action.action_id)

    key = json.dumps({"hdr.udp.dstPort": port})
    return key, action_name, {}

def parse_smac_lookup(entry, helper):
    mac = my_decode_mac(helper.get_match_field_value(entry.match[0]))
    action_name = helper.get_actions_name(entry.action.action.action_id)

    key = str(mac)
    return key, action_name, {}

def my_decode_mac(mac):
    return ":".join(f"{byte:02x}" for byte in mac)

def convert_to_hex(v: int) -> str:
    return f"0x{v:x}"

TABLE_PARSERS = {
    "MyIngress.ipv4Lpm": parse_ipv4_lpm,
    "MyIngress.labelLookup": parse_label_lookup,
    "MyIngress.internalMacLookup": parse_internal_mac,
    "MyIngress.tunnelLookup": parse_tunnel_lookup,
    "MyIngress.checkDirection": parse_check_direction,
    "MyIngress.allowedPortsTCP": parse_allowed_tcp,
    "MyIngress.allowedPortsUDP": parse_allowed_udp,
    "MyIngress.sMacLookup": parse_smac_lookup,
}