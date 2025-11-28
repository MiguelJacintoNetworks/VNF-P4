#!/usr/bin/env python3

import argparse
import os
import sys
import json
import threading
from time import sleep
from pprint import pprint
import grpc
from scapy.all import Ether, Packet, BitField, raw

import reading_utils as rd
import writing_utils as wr

import urllib.request
import urllib.error

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

VMON_METRICS_URL = os.getenv("VMON_METRICS_URL", "http://10.0.250.2:5000/metrics")

VMON_IFACE_TO_SOURCE = {
    "vmon-eth0": "r4",
    "vmon-eth1": "r1",
}

BACKEND_IPS = {
    "10.0.2.1"
}

reported_suspicious_flows = set()

metrics_thread = None
metrics_stop_event = None

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "../utils/",
    )
)

class CpuHeader(Packet):
    name = "CpuPacket"
    fields_desc = [
        BitField("macAddr", 0, 48),
        BitField("ingressPort", 0, 16),
    ]

# VMON AUXILIAR METHOD

def handle_metrics():
    try:
        with urllib.request.urlopen(VMON_METRICS_URL, timeout = 2.0) as resp:
            body = resp.read()
            metrics = json.loads(body.decode("utf-8"))
    except urllib.error.URLError as e:
        print(f"METRICS ERROR FETCHING VMON METRICS: {e}")
        return
    except Exception as e:
        print(f"METRICS UNEXPECTED ERROR WHILE FETCHING VMON METRICS: {e}")
        return

    flows = metrics.get("flows", [])
    flow_count = metrics.get("flow_count", len(flows))
    generated_at = metrics.get("generated_at", "-")

    print("\n========== VMON METRICS ==========")
    print(f"GENERATED_AT : {generated_at}")
    print(f"FLOW_COUNT   : {flow_count}")
    print("----------------------------------")

    if not flows:
        print("NO FLOWS REPORTED BY VMON.")
        print("============ END ============\n")
        return

    for idx, f in enumerate(flows):
        proto = f.get("proto", "-")
        src_ip = f.get("src_ip", "-")
        dst_ip = f.get("dst_ip", "-")
        src_port = f.get("src_port", "-")
        dst_port = f.get("dst_port", "-")
        packets = f.get("packets", 0)
        bytes_ = f.get("bytes", 0)
        bps = f.get("bps", 0)
        syn_rtt_ms = f.get("syn_rtt_ms", None)

        first_iface = f.get("first_iface")
        last_iface = f.get("last_iface")
        iface = last_iface or first_iface or "-"
        source_node = VMON_IFACE_TO_SOURCE.get(iface, "-")

        print(f"[{idx}] {proto}  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"     PACKETS : {packets}")
        print(f"     BYTES   : {bytes_}")
        print(f"     BITRATE : {int(bps)} BPS")

        if syn_rtt_ms is not None:
            print(f"     SYN RTT : {syn_rtt_ms:.2f} MS")
        else:
            print("     SYN RTT : -")

        print(f"     IFACES  : FIRST = {first_iface or '-'} LAST = {last_iface or '-'}")
        print(f"     SOURCE  : {source_node} (via {iface})")

        print("----------------------------------")

    print("=========== END VMON ===========\n")

def poll_vmon_metrics(stop_event, interval=1.0):
    global reported_suspicious_flows
    while not stop_event.is_set():
        try:
            with urllib.request.urlopen(VMON_METRICS_URL, timeout=1.5) as resp:
                body = resp.read()
                metrics = json.loads(body.decode("utf-8"))
        except urllib.error.URLError as e:
            print(f"[VMON POLL] ERROR FETCHING METRICS: {e}")
            sleep(interval)
            continue
        except Exception as e:
            print(f"[VMON POLL] UNEXPECTED ERROR WHILE FETCHING METRICS: {e}")
            sleep(interval)
            continue

        flows = metrics.get("flows", [])

        for idx, f in enumerate(flows):
            proto = str(f.get("proto", "")).upper()
            if proto == "UDP":
                src_ip = f.get("src_ip", "-")
                dst_ip = f.get("dst_ip", "-")
                src_port = f.get("src_port", "-")
                dst_port = f.get("dst_port", "-")

                if dst_ip not in BACKEND_IPS:
                    continue

                flow_id = (src_ip, src_port, dst_ip, dst_port)

                if flow_id in reported_suspicious_flows:
                    continue

                reported_suspicious_flows.add(flow_id)

                first_iface = f.get("first_iface")
                last_iface = f.get("last_iface")
                iface = last_iface or first_iface or "-"
                source_node = VMON_IFACE_TO_SOURCE.get(iface, "-")

                print(
                    f"[VMON] PACKET SUSPICIOUS? UDP FLOW {idx}: "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                    f"[SOURCE = {source_node}, INTERFACE = {iface}]"
                )

        sleep(interval)

def load_config_files(switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path):
    switches_config = json.load(open(switches_config_path))
    program_config = load_program_config(switch_programs_path)
    tunnels_config = json.load(open(tunnels_config_path))
    clone_config = json.load(open(clone_config_path))
    return switches_config, program_config, tunnels_config, clone_config

def load_program_config(switch_programs_path):
    config_data = json.load(open(switch_programs_path))
    program_config = {}

    for sw_name, entry in config_data.items():
        helper_path = entry["p4info_path"]
        json_path = entry["json_path"]
        default_actions_path = entry["default_actions_path"]
        rules_path = entry["rules_path"]

        helper = p4runtime_lib.helper.P4InfoHelper(helper_path)

        program_config[sw_name] = {
            "helper": helper,
            "json": json_path,
            "default_actions": default_actions_path,
            "rules": rules_path,
        }

    return program_config

def setup_switches(connections, program_config, clone_config, clones, state, reset = False):
    install_p4_programs(connections, program_config, reset)
    write_clone_engines(connections, program_config, clone_config, clones, state)
    write_default_actions(connections, program_config, state)
    read_tables_rules(connections, program_config, state)
    write_static_rules(connections, program_config, state)

def create_connections_to_switches(switches_config, connections, state):
    print("------ CONNECTING TO DEVICES ------")

    connections.clear()

    for switch in switches_config:
        name = switch["name"]

        connections[name] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name = name,
            address = switch["address"],
            device_id = switch["device_id"],
            proto_dump_file = switch["proto_dump_file"],
        )

        connections[name].MasterArbitrationUpdate()
        state[name] = {}

    print("------ CONNECTION SUCCESSFUL ------\n")
    
def create_connection_to_switch(target, switches_config, connections, state):
    print("------ CONNECTING TO DEVICE ------")

    for switch in switches_config:
        if target == switch["name"]:
            connections[target] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name = target,
                address = switch["address"],
                device_id = switch["device_id"],
                proto_dump_file = switch["proto_dump_file"],
            )
            connections[target].MasterArbitrationUpdate()
            state[target] = {}
            break

    print("------ CONNECTION SUCCESSFUL ------\n")

def install_p4_programs(connections, program_config, reset = False):
    print("------ INSTALLING P4 PROGRAMS ------")

    for sw_name, sw_conn in connections.items():
        expected_helper = program_config[sw_name]["helper"]
        json_path = program_config[sw_name]["json"]

        if reset:
            print(f"{sw_name}: RESETTING SWITCH, INSTALLING P4 PROGRAM...")
        else:
            installed_p4info = sw_conn.GetInstalledP4Info()

            if installed_p4info is None:
                print(f"{sw_name}: NO P4 PROGRAM FOUND, INSTALLING...")
            elif installed_p4info != expected_helper.p4info:
                print(f"{sw_name}: DIFFERENT P4 PROGRAM FOUND, RE-INSTALLING...")
            else:
                print(f"{sw_name}: CORRECT P4 PROGRAM ALREADY INSTALLED, SKIPPING.")
                continue

        sw_conn.SetForwardingPipelineConfig(
            p4info = expected_helper.p4info,
            bmv2_json_file_path = json_path,
        )

        print(f"{sw_name}: P4 PROGRAM INSTALLED.")

    print("------ P4 PROGRAM INSTALLATION DONE ------\n")
    
def write_clone_engines(connections, program_config, clone_config, clones, state):
    print("------ INSTALLING MC GROUPS AND CLONE SESSIONS ------")

    for sw_name, sw in connections.items():
        if sw_name in clone_config:
            cfg = clone_config[sw_name]
            helper = program_config[sw_name]["helper"]

            if "mcSessionId" in cfg:
                mc_id = cfg["mcSessionId"]
                mc_replicas = cfg["broadcastReplicas"]
                wr.write_mc_group(helper, sw, mc_id, mc_replicas)

            if "cpuSessionId" in cfg:
                cpu_id = cfg["cpuSessionId"]
                cpu_replicas = cfg["cpuReplicas"]

                wr.write_cpu_session(helper, sw, cpu_id, cpu_replicas)

                clones.setdefault(sw_name, {})
                clones[sw_name]["id"] = cpu_id

                stop_event = threading.Event()
                clones[sw_name]["stop_event"] = stop_event

                thread = threading.Thread(
                    target = _listen_single_switch,
                    args = (program_config[sw_name]["helper"], connections[sw_name], clones, state),
                    daemon = True,
                )

                clones[sw_name]["thread"] = thread
                thread.start()

            if "vmonSessionId" in cfg:
                vmon_id = cfg["vmonSessionId"]
                vmon_replicas = cfg["vmonReplicas"]
                wr.write_cpu_session(helper, sw, vmon_id, vmon_replicas)
                print(f"VMON CLONE SESSION INSTALLED ON {sw_name}: SESSION {vmon_id}")

    print("------ MC GROUPS AND CLONE SESSIONS DONE ------\n")
                
def _listen_single_switch(helper, sw, clones, state):
    print(f"LISTENING FOR PACKET-INS ON {sw.name}")

    try:
        for response in sw.stream_msg_resp:
            if clones[sw.name]["stop_event"].is_set():
                break

            if response.packet:
                packet = Ether(raw(response.packet.payload))

                if packet.type == 0x1234:
                    cpu_header = CpuHeader(bytes(packet.load))
                    new_mac = cpu_header.macAddr
                    match_key = json.dumps({"hdr.eth.srcAddr": new_mac})

                    sw_state = state.setdefault(sw.name, {}).setdefault("MyIngress.sMacLookup", {})

                    if match_key not in sw_state:
                        wr.write_mac_src_lookup(helper, sw, new_mac)
                        wr.write_mac_dst_lookup(helper, sw, new_mac, cpu_header.ingressPort)

                        sw_state[match_key] = {
                            "action": "NoAction",
                            "params": {}
                        }
            else:
                print(f"{sw.name} RECEIVED NON PACKET-IN MESSAGE: {response}")

    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.CANCELLED:
            print(f"{sw.name} PACKET-IN STREAM CANCELLED, EXITING LISTENER")
        else:
            print(f"{sw.name} UNEXPECTED GRPC ERROR: {e}")

    finally:
        print(f"{sw.name} LISTENER THREAD TERMINATING")
        
def write_default_actions(connections, program_config, state):
    print("------ WRITING DEFAULT ACTIONS ------")

    for sw_name, sw in connections.items():
        helper = program_config[sw_name]["helper"]
        da_path = program_config[sw_name]["default_actions"]

        try:
            with open(da_path) as f:
                actions = json.load(f)
        except FileNotFoundError:
            print(f"NO DEFAULT ACTIONS CONFIG FOR {sw_name}, SKIPPING")
            continue

        for table_name, action_name in actions.items():
            state[sw_name][table_name] = {}
            wr.write_default_table_action(helper, sw, table_name, action_name)

    print("------ DEFAULT ACTIONS DONE ------\n")

def read_tables_rules(connections, program_config, state):
    print("------ READING TABLES RULES ------")

    for sw_name, sw in connections.items():
        helper = program_config[sw_name]["helper"]

        if not sw.HasP4ProgramInstalled():
            continue

        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table = helper.get_tables_name(entry.table_id)

                parser = rd.TABLE_PARSERS.get(table)

                if parser:
                    try:
                        key, action, params = parser(entry, helper)
                        state.setdefault(sw_name, {}).setdefault(table, {})[key] = {
                            "action": action,
                            "params": params
                        }
                    except Exception as e:
                        print(f"ERROR PARSING TABLE {table} ON {sw_name}: {e}")

    print("------ TABLE RULES READ DONE ------\n")
    
def write_static_rules(connections, program_config, state):
    print("------ WRITING STATIC RULES ------")

    for sw_name, switch in connections.items():
        helper = program_config[sw_name]["helper"]
        rules_path = program_config[sw_name]["rules"]

        try:
            with open(rules_path) as f:
                switch_rules = json.load(f)
        except FileNotFoundError:
            print(f"NO STATIC RULES CONFIG FOR {sw_name}, SKIPPING")
            continue

        for table, rules in switch_rules.items():
            for match, action_params in rules.items():
                match_dict = json.loads(match)
                action = action_params["action"]
                params = action_params["params"]

                wr.compare_and_write_rule(helper, switch, table, match_dict, action, params, state)

    print("------ STATIC RULES DONE ------\n")

def setup_tunnels(connections, program_config, tunnels_config, tunnels, state):
    init_tunnel_states(connections, program_config, tunnels_config, tunnels, state)
    change_tunnel_rules(connections, program_config, tunnels_config, tunnels, state)
    
def init_tunnel_states(connections, program_config, tunnels_config, tunnels, state):
    cfgs = tunnels_config["tunnels"]
    table = tunnels_config["table"]
    mf = tunnels_config["match_field"]

    tunnels.clear()

    for tcfg in cfgs:
        name = tcfg["name"]
        sw_a = tcfg["switchA"]

        state.setdefault(sw_a, {}).setdefault(table, {})

        found = None

        for s in tcfg["states"]:
            expected = {
                json.dumps({mf: int(k)}, sort_keys = True): v
                for k, v in s["labelsA"].items()
            }
            actual = {
                k: entry["params"]["labels"]
                for k, entry in state[sw_a][table].items()
            }
            if expected == actual:
                found = s["id"]
                break

        if found is None:
            s0 = tcfg["states"][0]
            print(f"{name} NO EXISTING CONFIG, INSTALLING INITIAL STATE 0")

            for side in ("A", "B"):
                sw = connections[tcfg[f"switch{side}"]]
                hlp = program_config[tcfg[f"switch{side}"]]["helper"]
                labels = s0[f"labels{side}"]

                for match_val, hexlbl in labels.items():
                    wr.write_table_entry(
                        hlp,
                        sw,
                        table,
                        {mf: int(match_val)},
                        "MyIngress.addMSLP",
                        {"labels": hexlbl},
                        modify = False
                    )

                    key = json.dumps({mf: int(match_val)}, sort_keys = True)
                    state[sw.name][table][key] = {
                        "action": "MyIngress.addMSLP",
                        "params": {"labels": hexlbl}
                    }

            found = 0

        else:
            print(f"{name} DETECTED EXISTING TUNNEL STATE {found}")

        tunnels.setdefault(name, {})
        tunnels[name]["state"] = found

def change_tunnel_rules(connections, program_config, tunnels_config, tunnels, state):
    tcfgs = tunnels_config["tunnels"]
    interval = tunnels_config["check_interval"]
    threshold = tunnels_config["threshold"]
    table = tunnels_config["table"]
    mf = tunnels_config["match_field"]
    cntr_name = tunnels_config["counter_name"]

    for tcfg in tcfgs:
        name = tcfg["name"]
        stop_event = threading.Event()

        tunnels[name]["stop_event"] = stop_event

        thread = threading.Thread(
            target = _monitor_single_tunnel,
            args = (
                connections,
                program_config,
                tcfg,
                interval,
                threshold,
                table,
                mf,
                cntr_name,
                tunnels,
                state,
            ),
            daemon = True
        )

        tunnels[name]["thread"] = thread
        thread.start()

def _monitor_single_tunnel(
    connections,
    program_config,
    tcfg,
    interval,
    threshold,
    table,
    mf,
    cntr_name,
    tunnels,
    state,
):
    name = tcfg["name"]
    idxs = tcfg["counter_index"]
    states = tcfg["states"]

    sw_a = connections[tcfg["switchA"]]
    sw_b = connections[tcfg["switchB"]]
    h_a = program_config[tcfg["switchA"]]["helper"]
    h_b = program_config[tcfg["switchB"]]["helper"]

    curr_state = tunnels[name]["state"]
    print(f"STARTING TUNNEL MONITOR {name} BETWEEN {sw_a.name} AND {sw_b.name}")

    while not tunnels[name]["stop_event"].is_set():
        up_a = rd.read_counter(h_a, sw_a, cntr_name, idxs["A_up"])
        down_a = rd.read_counter(h_a, sw_a, cntr_name, idxs["A_down"])
        up_b = rd.read_counter(h_b, sw_b, cntr_name, idxs["B_up"])
        down_b = rd.read_counter(h_b, sw_b, cntr_name, idxs["B_down"])

        total_up = up_a + up_b
        total_down = down_a + down_b

        print(f"\n[{name}] UP = {total_up}, DOWN = {total_down}")
        print(f"[{sw_a.name}] UP = {up_a}, DOWN = {down_a}")
        print(f"[{sw_b.name}] UP = {up_b}, DOWN = {down_b}")

        sleep_boost = 1

        if abs(total_up - total_down) > threshold:
            next_state = 1 - curr_state
            nxt = states[next_state]

            for sw, helper, labels in [
                (sw_a, h_a, nxt["labelsA"]),
                (sw_b, h_b, nxt["labelsB"]),
            ]:
                for match_val, lbl in labels.items():
                    wr.write_table_entry(
                        helper,
                        sw,
                        table,
                        {mf: int(match_val)},
                        "MyIngress.addMSLP",
                        {"labels": lbl},
                        modify = True,
                    )

                    key = json.dumps({mf: int(match_val)}, sort_keys = True)

                    state[sw.name][table][key] = {
                        "action": "MyIngress.addMSLP",
                        "params": {"labels": lbl},
                    }

            curr_state = next_state
            tunnels[name]["state"] = next_state
            sleep_boost = 3
            print(f"[{name}] SWITCHED TO STATE {curr_state}\n")
        else:
            print(f"[{name}] NO STATE SWITCH NEEDED\n")

        sleep(interval * sleep_boost)
        
def full_reset(
    switches_config_path,
    switch_programs_path,
    tunnels_config_path,
    clone_config_path,
    connections,
    clones,
    tunnels,
    state,
):
    print("PERFORMING FULL RESET OF CONTROLLER AND SWITCHES")

    stop_tunnel_monitor_threads(tunnels)
    ShutdownAllSwitchConnections()
    stop_clone_engine_threads(clones)

    switches_config, program_config, tunnels_config, clone_config = load_config_files(
        switches_config_path,
        switch_programs_path,
        tunnels_config_path,
        clone_config_path,
    )

    create_connections_to_switches(switches_config, connections, state)
    setup_switches(connections, program_config, clone_config, clones, state, reset = True)
    setup_tunnels(connections, program_config, tunnels_config, tunnels, state)

    print("ALL SWITCHES HAVE BEEN RESET")
    return switches_config, program_config, tunnels_config, clone_config

def reset_switch(
    sw_name,
    switches_config_path,
    switch_programs_path,
    tunnels_config_path,
    clone_config_path,
    old_program_config,
    old_tunnels_config,
    connections,
    clones,
    tunnels,
    state,
):
    print(f"RESETTING SWITCH {sw_name}")

    clean_tunnel_rules(
        old_tunnels_config["table"],
        connections,
        old_program_config,
        tunnels,
        state,
    )

    connections[sw_name].shutdown()
    stop_clone_engine_thread_switch(sw_name, clones)

    switches_config, program_config, tunnels_config, clone_config = load_config_files(
        switches_config_path,
        switch_programs_path,
        tunnels_config_path,
        clone_config_path,
    )

    create_connection_to_switch(sw_name, switches_config, connections, state)

    sw_conn = {sw_name: connections[sw_name]}
    sw_program_cfg = {sw_name: program_config[sw_name]}

    setup_switches(sw_conn, sw_program_cfg, clone_config, clones, state, reset = True)
    setup_tunnels(connections, program_config, tunnels_config, tunnels, state)

    print(f"SWITCH {sw_name} HAS BEEN RESET")
    return switches_config, program_config, tunnels_config, clone_config

def reset_all_counters(connections, program_config, tunnels_config):
    counter_name = tunnels_config["counter_name"]

    for tcfg in tunnels_config["tunnels"]:
        for side, role in [("switchA", "A"), ("switchB", "B")]:
            sw_name = tcfg[side]
            helper = program_config[sw_name]["helper"]
            sw = connections[sw_name]
            idxs = tcfg["counter_index"]

            wr.reset_counter(helper, sw, counter_name, idxs[f"{role}_up"])
            wr.reset_counter(helper, sw, counter_name, idxs[f"{role}_down"])
            
def clean_tunnel_rules(table_name, connections, program_config, tunnels, state):
    print("CLEANING ALL TUNNEL RULES FROM ALL SWITCHES")

    for tname, tinfo in list(tunnels.items()):
        tinfo["stop_event"].set()
        tinfo["thread"].join()
        print(f"STOPPED TUNNEL MONITOR FOR {tname}")

    tunnels.clear()

    for sw_name, sw in connections.items():
        table_state = state.get(sw_name, {}).get(table_name, {})

        for key_str in list(table_state.keys()):
            match_fields = json.loads(key_str)

            try:
                entry = program_config[sw_name]["helper"].buildTableEntry(
                    table_name = table_name,
                    match_fields = match_fields,
                    default_action = False,
                )

                sw.DeleteTableEntry(entry)
                del table_state[key_str]

                print(f"REMOVED TUNNEL RULE {match_fields} FROM {sw_name}")
            except Exception as e:
                print(f"ERROR REMOVING RULE {match_fields} FROM {sw_name}: {e}")
                
def stop_clone_engine_thread_switch(sw_name, clones):
    if sw_name in clones:
        clones[sw_name]["stop_event"].set()
        clones[sw_name]["thread"].join()
        del clones[sw_name]
    
def stop_clone_engine_threads(clones):
    for sw_name, clone in list(clones.items()):
        clone["stop_event"].set()
        clone["thread"].join()
        print(f"STOPPED PACKET-IN LISTENER FOR {sw_name}")

    clones.clear()

def stop_tunnel_monitor_threads(tunnels):
    for tname, tinfo in list(tunnels.items()):
        tinfo["stop_event"].set()
        tinfo["thread"].join()
        print(f"STOPPED TUNNEL MONITOR FOR {tname}")

    tunnels.clear()

def handle_reset(
    target,
    switches_config_path,
    switch_programs_path,
    tunnels_config_path,
    clone_config_path,
    switches_config,
    program_config,
    tunnels_config,
    clone_config,
    connections,
    clones,
    tunnels,
    state,
):
    if target == "all":
        switches_config, program_config, tunnels_config, clone_config = full_reset(
            switches_config_path,
            switch_programs_path,
            tunnels_config_path,
            clone_config_path,
            connections,
            clones,
            tunnels,
            state,
        )

    elif target == "tunnels":
        clean_tunnel_rules(
            tunnels_config["table"],
            connections,
            program_config,
            tunnels,
            state,
        )
        setup_tunnels(
            connections,
            program_config,
            tunnels_config,
            tunnels,
            state,
        )

    elif target == "counters":
        reset_all_counters(connections, program_config, tunnels_config)

    elif target in connections:
        switches_config, program_config, tunnels_config, clone_config = reset_switch(
            target,
            switches_config_path,
            switch_programs_path,
            tunnels_config_path,
            clone_config_path,
            program_config,
            tunnels_config,
            connections,
            clones,
            tunnels,
            state,
        )

    else:
        print(f"UNKNOWN TARGET FOR RESET {target}")

    return switches_config, program_config, tunnels_config, clone_config

def handle_show(target, connections, program_config, state):
    if target == "state":
        print("---------- CONTROLLER STATE ----------")
        pprint(state)
        print("")
    elif target in connections:
        helper = program_config[target]["helper"]
        rd.print_table_rules(helper, connections[target])
    else:
        print(f"UNKNOWN SHOW TARGET {target}")

def graceful_shutdown(clones, tunnels):
    print("SHUTTING DOWN...")

    ShutdownAllSwitchConnections()
    stop_clone_engine_threads(clones)
    stop_tunnel_monitor_threads(tunnels)

    if metrics_stop_event is not None:
        metrics_stop_event.set()
    if metrics_thread is not None and metrics_thread.is_alive():
        metrics_thread.join()

    print("CONTROLLER EXITED CLEANLY")

def traffic_control(action):
    path_map = {
        "wget_on": "/traffic/wget/start",
        "wget_off": "/traffic/wget/stop",
        "iperf_on": "/traffic/iperf/start",
        "iperf_off": "/traffic/iperf/stop",
    }

    if action not in path_map:
        print(f"TRAFFIC UNKNOWN ACTION {action}")
        return

    url = f"http://127.0.0.1:9000{path_map[action]}"

    try:
        req = urllib.request.Request(url, data = b"", method = "POST")
        with urllib.request.urlopen(req, timeout = 2.0) as resp:
            body = resp.read().decode("utf-8", errors = "ignore")
            print(f"TRAFFIC {body}")
    except Exception as e:
        print(f"TRAFFIC ERROR CONTACTING TRAFFIC CONTROLLER: {e}")
        
def main(switches_config_path, switch_programs_path, tunnels_config_path, clone_config_path):
    switches_config = {}
    program_config = {}
    clone_config = {}
    tunnels_config = {}
    state = {}
    connections = {}
    tunnels = {}
    clones = {}

    try:
        switches_config, program_config, tunnels_config, clone_config = load_config_files(
            switches_config_path,
            switch_programs_path,
            tunnels_config_path,
            clone_config_path,
        )

        create_connections_to_switches(switches_config, connections, state)
        setup_switches(connections, program_config, clone_config, clones, state)
        setup_tunnels(connections, program_config, tunnels_config, tunnels, state)

        global metrics_thread, metrics_stop_event
        metrics_stop_event = threading.Event()
        metrics_thread = threading.Thread(
            target=poll_vmon_metrics,
            args=(metrics_stop_event, 1.0),
            daemon=True,
        )
        metrics_thread.start()
        print("[VMON POLL] STARTED BACKGROUND METRICS POLLING")

        while True:
            try:
                user_input = input("\nCONTROLLER> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nCLI INTERRUPT RECEIVED. SHUTTING DOWN NOW...")
                graceful_shutdown(clones, tunnels)
                break

            if not user_input:
                continue

            parts = user_input.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("help", "?"):
                print("\nAVAILABLE COMMANDS:")
                print("  RESET <TARGET>        - RESET ALL | TUNNELS | COUNTERS | <SWITCH_NAME>")
                print("  SHOW <TARGET>         - SHOW STATE | <SWITCH_NAME>")
                print("  METRICS               - SHOW FULL VMON METRICS SNAPSHOT")
                print("  TRAFFIC WGET ON|OFF   - CONTROL SEQUENTIAL HTTP (WGET) TRAFFIC")
                print("  TRAFFIC IPERF ON|OFF  - CONTROL SEQUENTIAL IPERF TRAFFIC")
                print("  EXIT | QUIT | Q       - TERMINATE CONTROLLER")
                print("")
                continue

            if cmd == "reset":
                if len(args) != 1:
                    print("CLI INVALID SYNTAX FOR RESET")
                    print("USAGE: RESET <ALL|TUNNELS|COUNTERS|SWITCH_NAME>")
                    continue

                target = args[0]

                switches_config, program_config, tunnels_config, clone_config = handle_reset(
                    target,
                    switches_config_path,
                    switch_programs_path,
                    tunnels_config_path,
                    clone_config_path,
                    switches_config,
                    program_config,
                    tunnels_config,
                    clone_config,
                    connections,
                    clones,
                    tunnels,
                    state,
                )
                continue

            if cmd == "show":
                if len(args) != 1:
                    print("CLI INVALID SYNTAX FOR SHOW")
                    print("USAGE: SHOW <STATE|SWITCH_NAME>")
                    continue

                target = args[0]
                handle_show(target, connections, program_config, state)
                continue

            if cmd == "metrics":
                if len(args) != 0:
                    print("CLI INVALID SYNTAX FOR METRICS")
                    print("USAGE: METRICS")
                    continue

                handle_metrics()
                continue

            if cmd == "traffic":
                if len(args) != 2:
                    print("CLI INVALID SYNTAX FOR TRAFFIC")
                    print("USAGE: TRAFFIC <WGET|IPERF> <ON|OFF>")
                    continue

                kind = args[0].lower()
                mode = args[1].lower()

                if kind not in ("wget", "iperf") or mode not in ("on", "off"):
                    print("CLI INVALID TRAFFIC ARGUMENTS")
                    print("USAGE: TRAFFIC <WGET|IPERF> <ON|OFF>")
                    continue

                action = f"{kind}_{'on' if mode == 'on' else 'off'}"
                traffic_control(action)
                continue

            if cmd in ("exit", "quit", "q"):
                print("CLI CONTROLLER EXIT REQUESTED. SHUTTING DOWN...")
                graceful_shutdown(clones, tunnels)
                break

            print(f"CLI UNKNOWN COMMAND {user_input}")
            print("TYPE HELP TO SEE AVAILABLE COMMANDS")

    except KeyboardInterrupt:
        print("CONTROLLER INTERRUPTED BY USER")
        graceful_shutdown(clones, tunnels)

    except grpc.RpcError as e:
        print("GRPC ERROR:", e.details(), end = " ")
        status_code = e.code()
        print(f"({status_code.name})", end = " ")
        traceback = sys.exc_info()[2]
        print(f"[{traceback.tb_frame.f_code.co_filename}:{traceback.tb_lineno}]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "P4Runtime Controller")

    parser.add_argument(
        "--config",
        type = str,
        action = "store",
        required = True,
        help = "json file with the switches configuration",
    )
    parser.add_argument(
        "--programs",
        type = str,
        action = "store",
        required = True,
        help = "json file with the P4 programs configuration",
    )
    parser.add_argument(
        "--tunnels",
        type = str,
        action = "store",
        required = True,
        help = "json file with the tunnels configuration",
    )
    parser.add_argument(
        "--clone",
        type = str,
        action = "store",
        required = True,
        help = "json file with the mc and clone sessions configuration",
    )

    args = parser.parse_args()

    if not os.path.exists(args.config):
        parser.print_help()
        print("\nCONFIG FILE NOT FOUND")
        parser.exit(1)

    if not os.path.exists(args.programs):
        parser.print_help()
        print("\nPROGRAMS FILE NOT FOUND")
        parser.exit(1)

    if not os.path.exists(args.tunnels):
        parser.print_help()
        print("\nTUNNELS FILE NOT FOUND")
        parser.exit(1)

    if not os.path.exists(args.clone):
        parser.print_help()
        print("\nCLONE FILE NOT FOUND")
        parser.exit(1)

    main(args.config, args.programs, args.tunnels, args.clone)