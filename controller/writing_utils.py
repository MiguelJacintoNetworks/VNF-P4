import json 

def reset_counter(p4info_helper, sw, counter_name, idx):
    counter_id = p4info_helper.get_counters_id(counter_name)
    sw.WriteCounterEntry(counter_id, idx)
    print(f"RESET COUNTER {counter_name} IDX = {idx} ON {sw.name}")
    
def write_mc_group(p4info_helper, sw, session_id, broadcast_replicas):
    if not sw.isMulticastGroupInstalled(session_id):
        mc_group = p4info_helper.buildMulticastGroupEntry(session_id, broadcast_replicas)
        sw.WritePREEntry(mc_group)
        print(f"INSTALLED MULTICAST GROUP {session_id} ON {sw.name}")

def write_cpu_session(p4info_helper, sw, session_id, cpu_replicas):
    if not sw.isCloneSessionInstalled(session_id):
        clone_entry = p4info_helper.buildCloneSessionEntry(session_id, cpu_replicas)
        sw.WritePREEntry(clone_entry)
        print(f"INSTALLED CLONE SESSION {session_id} ON {sw.name}")

def write_default_table_action(p4info_helper, sw, table, intended_action):
    table_id = p4info_helper.get_tables_id(table)
    current_action_id = sw.getDefaultAction(table_id).action.action.action_id
    intended_action_id = p4info_helper.get_actions_id(intended_action)

    if current_action_id != intended_action_id:
        table_entry = p4info_helper.buildTableEntry(
            table_name = table,
            default_action = True,
            action_name = intended_action,
        )
        sw.WriteTableEntry(table_entry)
        print(f"UPDATED DEFAULT ACTION IN {table} ON {sw.name} TO {intended_action}")
        
def compare_and_write_rule(helper, switch, table, match, expected_action, expected_params, state):
    current_state = state[switch.name][table]

    match_str = json.dumps(match, sort_keys = True)

    if match_str in current_state:
        current_action = current_state[match_str]["action"]
        current_params = current_state[match_str]["params"]

        if current_action != expected_action or current_params != expected_params:
            print(f"UPDATING RULE ON {switch.name} FOR TABLE {table}")
            write_table_entry(helper, switch, table, match, expected_action, expected_params, modify = True)
            current_state[match_str] = {
                "action": expected_action,
                "params": expected_params,
            }
    else:
        print(f"ADDING RULE TO {switch.name} FOR TABLE {table}")
        write_table_entry(helper, switch, table, match, expected_action, expected_params)
        current_state[match_str] = {
            "action": expected_action,
            "params": expected_params,
        }
        
def write_table_entry(helper, sw, table, match, action, params, dryrun = False, modify = False):
    match = normalize_hex_strings(match)
    params = normalize_hex_strings(params)

    table_entry = helper.buildTableEntry(
        table_name = table,
        match_fields = match,
        default_action = False,
        action_name = action,
        action_params = params,
        priority = 0,
    )
    sw.WriteTableEntry(table_entry, dryrun, modify)
    
def write_mac_dst_lookup(p4info_helper, sw, mac, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.dMacLookup",
        match_fields = {
            "hdr.eth.dstAddr": mac,
        },
        default_action = False,
        action_name = "MyIngress.forward",
        action_params = {
            "egressPort": port,
        },
        priority = 0,
    )
    sw.WriteTableEntry(table_entry)
    print(f"INSTALLED MAC DST RULES ON {sw.name}")

def write_mac_src_lookup(p4info_helper, sw, mac):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "MyIngress.sMacLookup",
        match_fields = {
            "hdr.eth.srcAddr": mac,
        },
        default_action = False,
        action_name = "NoAction",
        action_params = None,
        priority = 0,
    )
    sw.WriteTableEntry(table_entry)
    print(f"INSTALLED MAC SRC RULES ON {sw.name}")

def normalize_hex_strings(param: dict) -> dict:
    if not param:
        return {}

    new_param = {}

    for k, v in param.items():
        if isinstance(v, str) and v.startswith("0x"):
            new_param[k] = int(v, 16)
        else:
            new_param[k] = v

    return new_param