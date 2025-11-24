#!/usr/bin/env python3


from mininet.net import Mininet
from mininet.net import Containernet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import Host

from p4_mininet import P4Host
from p4runtime_switch import P4RuntimeSwitch
from http.server import BaseHTTPRequestHandler, HTTPServer

import argparse
import os
import glob
import threading
from time import sleep

wget_stop_event = threading.Event()
iperf_stop_event = threading.Event()
wget_thread = None
iperf_thread = None

# If you look at this parser, it can identify 4 arguments
# --behavioral-exe, with the default value 'simple_switch'
## this indicates that the arch of our software switch is the 'simple_switch'
## and any p4 program made for this arch needs to be compiled against de 'v1model.p4'
# --thrift-port, with the default value of 9090, which is the default server port of
## a thrift server - the P4Switch instantiates a Thrift server that allows us
## to communicate our P4Switch (software switch) at runtime
# --num-hosts, with default value 2 indicates the number of hosts...
# --json, is the path to JSON config file - the output of your p4 program compilation
## this is the only argument that you will need to pass in orther to run the script
parser = argparse.ArgumentParser(description='Mininet demo')

# Argument to specify the path to the behavioral executable (the P4 program executable)
# Use the default value
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", default='simple_switch_grpc')
# Argument to specify the Thrift server port for table updates (default 9090)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
# Argument to specify the gRPC server port for controller communication (default 50051)
parser.add_argument('--grpc-port', help='gRPC server port for controller comm',
                        type=int, action="store", default=50051)

args = parser.parse_args()

sw_mac_base = "cc:00:00:00:01:%02x"
mac_base = "aa:00:00:00:%02x:%02x"

host_ip_base = "10.0.%d.%d/24"

def disable_rp_filter_for_veth():
    os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
    for d in glob.glob("/proc/sys/net/ipv4/conf/veth*"):
        rp_file = os.path.join(d, "rp_filter")
        if os.path.isfile(rp_file):
            os.system(f"echo 0 > {rp_file}")

class SingleSwitchTopo(Topo):
    def __init__(self, sw_path, thrift_port, grpc_port, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        # Add switches/routers
        s1 = self.addSwitch('s1',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port,
                                grpc_port = grpc_port,
                                device_id = 1,
                                cpu_port = 510)
        
        r1 = self.addSwitch('r1',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 1,
                                grpc_port = grpc_port + 1,
                                device_id = 2,
                                cpu_port = 510)
        r2 = self.addSwitch('r2',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 2,
                                grpc_port = grpc_port + 2,
                                device_id = 3,
                                cpu_port = 510)
        r3 = self.addSwitch('r3',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 3,
                                grpc_port = grpc_port + 3,
                                device_id = 4,
                                cpu_port = 510)
        r4 = self.addSwitch('r4',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 4,
                                grpc_port = grpc_port + 4,
                                device_id = 5,
                                cpu_port = 510)
        r5 = self.addSwitch('r5',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 5,
                                grpc_port = grpc_port + 5,
                                device_id = 6,
                                cpu_port = 510)
        r6 = self.addSwitch('r6',
                                cls = P4RuntimeSwitch,
                                sw_path = sw_path,
                                thrift_port = thrift_port + 6,
                                grpc_port = grpc_port + 6,
                                device_id = 7,
                                cpu_port = 510)
        
        # Add hosts
        h1 = self.addHost('h1',
                    ip = host_ip_base % (1,1),
                    mac = mac_base % (0,1))
        h2 = self.addHost('h2',
                    ip = host_ip_base % (1,2),
                    mac = mac_base % (0,2))
        h3 = self.addHost('h3',
                    ip = host_ip_base % (1,3),
                    mac = mac_base % (0,3))
        h4 = self.addHost('h4',
                    cls = Host,
                    ip = "10.0.4.2/30",
                    mac = mac_base % (0,4))
        h5 = self.addHost('h5',
                    cls = Host,
                    ip = "10.0.5.2/30",
                    mac = mac_base % (0,5))
        h6 = self.addHost('h6',
                    cls = Host,
                    ip = "10.0.6.2/30",
                    mac = mac_base % (0,6))  

        # Add links
        self.addLink(h1, s1, port2= 1, addr2= sw_mac_base % 1)
        self.addLink(h2, s1, port2= 2, addr2= sw_mac_base % 2)
        self.addLink(h3, s1, port2= 3, addr2= sw_mac_base % 3)
        
        self.addLink(s1, r1, port1= 4, port2= 1, addr1= sw_mac_base % 4, addr2= mac_base % (1,1))
        self.addLink(r1, r2, port1= 2, port2= 1, addr1= mac_base % (1,2), addr2= mac_base % (2,1))
        self.addLink(r1, r6, port1= 3, port2= 1, addr1= mac_base % (1,3), addr2= mac_base % (6,1))
        self.addLink(r2, r3, port1= 2, port2= 1, addr1= mac_base % (2,2), addr2= mac_base % (3,1))
        self.addLink(r3, r4, port1= 2, port2= 3, addr1= mac_base % (3,2), addr2= mac_base % (4,3))
        self.addLink(r4, r5, port1= 2, port2= 2, addr1= mac_base % (4,2), addr2= mac_base % (5,2))
        self.addLink(r5, r6, port1= 1, port2= 2, addr1= mac_base % (5,1), addr2= mac_base % (6,2))

        # self.addLink(h4, r4, port2= 1, addr2= mac_base % (4,1))

        
def main():

    # Initialize the custom topology with the provided arguments
    topo = SingleSwitchTopo(args.behavioral_exe,
                            args.thrift_port,
                            args.grpc_port)

    # the host class is the P4Host
    net = Containernet(topo = topo,
                  host = P4Host,
                  controller = None)

    vlb = net.addDocker(
        'vlb',
        dimage='vnf',
        dcmd='/entrypoint.sh',
        docker_args={
            'network_mode': 'none',
            'privileged': True
        }
    )

    vmon = net.addDocker(
        'vmon',
        dimage='vnf',
        dcmd='/entrypoint.sh',
        docker_args={
            'network_mode': 'none',
            'privileged': True
        }
    )

    r1 = net.get('r1')
    r2 = net.get('r2')
    r3 = net.get('r3')
    r4 = net.get('r4')
    r5 = net.get('r5')
    r6 = net.get('r6')
    s1 = net.get('s1')
    h4 = net.get('h4')
    h5 = net.get('h5')
    h6 = net.get('h6')

    net.addLink(
        r4, vmon,
        port1=4,
        addr1=mac_base % (4,4),
        addr2="aa:00:00:00:20:01"
    )

    net.addLink(
        r4, vlb,
        port1=1,
        addr1=mac_base % (4,1),
        addr2="aa:00:00:00:10:01"
    )

    net.addLink(
        vlb, h4,
        addr1="aa:00:00:00:10:02",
        addr2=mac_base % (0,4)
    )

    net.addLink(
        vlb, h5,
        addr1="aa:00:00:00:10:03",
        addr2=mac_base % (0,5)
    )

    net.addLink(
        vlb, h6,
        addr1="aa:00:00:00:10:04",
        addr2=mac_base % (0,6)
    )

    disable_rp_filter_for_veth()

    # Here, the mininet will use the constructor (__init__()) of the P4Switch class, 
    # with the arguments passed to the SingleSwitchTopo class in order to create 
    # our software switch.
    net.start()
    
    sleep(1)  # time for the host and switch confs to take effect

    # Configurar ARP tables dos hosts

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    h1.setARP("10.0.1.254", "aa:00:00:00:01:01")
    h2.setARP("10.0.1.254", "aa:00:00:00:01:01")
    h3.setARP("10.0.1.254", "aa:00:00:00:01:01")
    
    h1.setDefaultRoute("dev eth0 via 10.0.1.254")
    h2.setDefaultRoute("dev eth0 via 10.0.1.254")
    h3.setDefaultRoute("dev eth0 via 10.0.1.254")

    vmon.cmd("ip link set dev eth0 down || true")
    vmon.cmd("ip addr flush dev vmon-eth0 || true")
    vmon.cmd("ip link set vmon-eth0 up")
    vmon.cmd("ip addr add 10.0.250.2/24 dev vmon-eth0")
    vmon.cmd("ip link set vmon-eth0 promisc on")

    vmon.cmd("ethtool -K vmon-eth0 rx off tx off tso off gso off gro off || true")

    r4.cmd("ip link set r4-eth4 up")
    r4.cmd("ip addr add 10.0.250.1/24 dev r4-eth4")

    vlb.cmd("ip link set dev eth0 down || true")

    vlb.cmd("ip link set dev vlb-eth0 up")
    vlb.cmd("ip addr add 10.0.2.1/24 dev vlb-eth0")
    vlb.cmd("ip neigh add 10.0.2.254 lladdr aa:00:00:00:04:01 dev vlb-eth0")
    vlb.cmd("ip route add default via 10.0.2.254 dev vlb-eth0")

    vlb.cmd("ip link set dev vlb-eth1 up")
    vlb.cmd("ip addr add 10.0.4.1/30 dev vlb-eth1")
    vlb.cmd("ip neigh add 10.0.4.2 lladdr aa:00:00:00:00:04 dev vlb-eth1")

    vlb.cmd("ip link set dev vlb-eth2 up")
    vlb.cmd("ip addr add 10.0.5.1/30 dev vlb-eth2")
    vlb.cmd("ip neigh add 10.0.5.2 lladdr aa:00:00:00:00:05 dev vlb-eth2")

    vlb.cmd("ip link set dev vlb-eth3 up")
    vlb.cmd("ip addr add 10.0.6.1/30 dev vlb-eth3")
    vlb.cmd("ip neigh add 10.0.6.2 lladdr aa:00:00:00:00:06 dev vlb-eth3")

    vlb.cmd("ethtool -K vlb-eth0 rx off tx off tso off gso off gro off || true")
    vlb.cmd("ethtool -K vlb-eth1 rx off tx off tso off gso off gro off || true")
    vlb.cmd("ethtool -K vlb-eth2 rx off tx off tso off gso off gro off || true")
    vlb.cmd("ethtool -K vlb-eth3 rx off tx off tso off gso off gro off || true")

    h4.cmd("ip addr flush dev h4-eth0")
    h4.cmd("ip addr add 10.0.4.2/30 dev h4-eth0")
    h4.cmd("ip link set h4-eth0 up")
    h4.cmd("ip neigh add 10.0.4.1 lladdr aa:00:00:00:10:02 dev h4-eth0")
    h4.cmd("ip route add default via 10.0.4.1 dev h4-eth0")

    h5.cmd("ip addr flush dev h5-eth0")
    h5.cmd("ip addr add 10.0.5.2/30 dev h5-eth0")
    h5.cmd("ip link set h5-eth0 up")
    h5.cmd("ip neigh add 10.0.5.1 lladdr aa:00:00:00:10:03 dev h5-eth0")
    h5.cmd("ip route add default via 10.0.5.1 dev h5-eth0")

    h6.cmd("ip addr flush dev h6-eth0")
    h6.cmd("ip addr add 10.0.6.2/30 dev h6-eth0")
    h6.cmd("ip link set h6-eth0 up")
    h6.cmd("ip neigh add 10.0.6.1 lladdr aa:00:00:00:10:04 dev h6-eth0")
    h6.cmd("ip route add default via 10.0.6.1 dev h6-eth0")

    h4.cmd("ethtool -K h4-eth0 rx off tx off tso off gso off gro off || true")
    h5.cmd("ethtool -K h5-eth0 rx off tx off tso off gso off gro off || true")
    h6.cmd("ethtool -K h6-eth0 rx off tx off tso off gso off gro off || true")

    r1.cmd("ethtool -K r1-eth1 rx off tx off tso off gso off gro off || true")
    r1.cmd("ethtool -K r1-eth2 rx off tx off tso off gso off gro off || true")
    r1.cmd("ethtool -K r1-eth3 rx off tx off tso off gso off gro off || true")

    r2.cmd("ethtool -K r2-eth1 rx off tx off tso off gso off gro off || true")
    r2.cmd("ethtool -K r2-eth2 rx off tx off tso off gso off gro off || true")

    r3.cmd("ethtool -K r3-eth1 rx off tx off tso off gso off gro off || true")
    r3.cmd("ethtool -K r3-eth2 rx off tx off tso off gso off gro off || true")

    r4.cmd("ethtool -K r4-eth1 rx off tx off tso off gso off gro off || true")
    r4.cmd("ethtool -K r4-eth2 rx off tx off tso off gso off gro off || true")
    r4.cmd("ethtool -K r4-eth2 rx off tx off tso off gso off gro off || true")
    r4.cmd("ethtool -K r4-eth4 rx off tx off tso off gso off gro off || true")
    
    r5.cmd("ethtool -K r5-eth1 rx off tx off tso off gso off gro off || true")
    r5.cmd("ethtool -K r5-eth2 rx off tx off tso off gso off gro off || true")

    r6.cmd("ethtool -K r6-eth1 rx off tx off tso off gso off gro off || true")
    r6.cmd("ethtool -K r6-eth2 rx off tx off tso off gso off gro off || true")

    h1.cmd("ethtool -K eth0 rx off tx off tso off gso off gro off || true")
    h2.cmd("ethtool -K eth0 rx off tx off tso off gso off gro off || true")
    h3.cmd("ethtool -K eth0 rx off tx off tso off gso off gro off || true")

    s1.cmd("ethtool -K s1-eth1 rx off tx off tso off gso off gro off || true")
    s1.cmd("ethtool -K s1-eth2 rx off tx off tso off gso off gro off || true")
    s1.cmd("ethtool -K s1-eth3 rx off tx off tso off gso off gro off || true")
    s1.cmd("ethtool -K s1-eth4 rx off tx off tso off gso off gro off || true")

    vlb.cmd("iptables -t nat -F")
    vlb.cmd("iptables -t nat -X")

    vlb.cmd("ipvsadm -C || true")

    vlb.cmd("ipvsadm -A -t 10.0.2.1:81 -s rr")

    vlb.cmd("ipvsadm -a -t 10.0.2.1:81 -r 10.0.4.2:81 -m")
    vlb.cmd("ipvsadm -a -t 10.0.2.1:81 -r 10.0.5.2:81 -m")
    vlb.cmd("ipvsadm -a -t 10.0.2.1:81 -r 10.0.6.2:81 -m")

    vlb.cmd("ipvsadm -A -t 10.0.2.1:5001 -s rr")
    vlb.cmd("ipvsadm -a -t 10.0.2.1:5001 -r 10.0.4.2:5001 -m")
    vlb.cmd("ipvsadm -a -t 10.0.2.1:5001 -r 10.0.5.2:5001 -m")
    vlb.cmd("ipvsadm -a -t 10.0.2.1:5001 -r 10.0.6.2:5001 -m")

    print("[TRAFFIC] STARTING BACKGROUND IPERF3 TRAFFIC...")

    h4.cmd("python3 -m http.server 81 >/dev/null 2>&1 &")
    h5.cmd("python3 -m http.server 81 >/dev/null 2>&1 &")
    h6.cmd("python3 -m http.server 81 >/dev/null 2>&1 &")

    h4.cmd("pkill -9 iperf >/dev/null 2>&1 || true")
    h5.cmd("pkill -9 iperf >/dev/null 2>&1 || true")
    h6.cmd("pkill -9 iperf >/dev/null 2>&1 || true")

    h4.cmd("iperf -s -p 5001 --daemon")
    h5.cmd("iperf -s -p 5001 --daemon")
    h6.cmd("iperf -s -p 5001 --daemon")

    def wget_sequential_loop():
        hosts = [("H1", h1), ("H2", h2), ("H3", h3)]
        while not wget_stop_event.is_set():
            for name, host in hosts:
                if wget_stop_event.is_set():
                    break
                print(f"\n[WGET][{name}] HTTP GET http://10.0.2.1:81/")
                out = host.cmd("wget -S -O /dev/null http://10.0.2.1:81/ 2>&1")
                print(f"[WGET][{name}] RESPONSE:\n{out}")
                print(f"[WGET][{name}] DONE\n" + "=" * 60)
                sleep(1)

        print("[WGET] LOOP STOPPED")

    def iperf_sequential_loop():
        hosts = [("H1", h1), ("H2", h2), ("H3", h3)]
        while not iperf_stop_event.is_set():
            for name, host in hosts:
                if iperf_stop_event.is_set():
                    break
                print(f"\n[IPERF][{name}] TEST TO 10.0.2.1:81")
                out = host.cmd("iperf -c 10.0.2.1 -p 5001 -M 500 -t 5 -i 1 2>&1")
                print(f"[IPERF][{name}] RESULT:\n{out}")
                print(f"[IPERF][{name}] DONE\n" + "=" * 60)
                sleep(1)

        print("[IPERF] LOOP STOPPED")

    def start_wget_loop():
        global wget_thread
        if wget_thread is not None and wget_thread.is_alive():
            print("[WGET] LOOP ALREADY RUNNING")
            return
        wget_stop_event.clear()
        wget_thread = threading.Thread(target=wget_sequential_loop, daemon=True)
        wget_thread.start()
        print("[WGET] LOOP STARTED")

    def stop_wget_loop():
        if wget_thread is None:
            print("[WGET] NO LOOP TO STOP")
            return
        wget_stop_event.set()
        h1.cmd("pkill -9 wget || true")
        h2.cmd("pkill -9 wget || true")
        h3.cmd("pkill -9 wget || true")
        print("[WGET] STOP SIGNAL SENT")

    def start_iperf_loop():
        global iperf_thread
        if iperf_thread is not None and iperf_thread.is_alive():
            print("[IPERF] LOOP ALREADY RUNNING")
            return
        iperf_stop_event.clear()
        iperf_thread = threading.Thread(target=iperf_sequential_loop, daemon=True)
        iperf_thread.start()
        print("[IPERF] LOOP STARTED")

    def stop_iperf_loop():
        if iperf_thread is None:
            print("[IPERF] NO LOOP TO STOP")
            return
        iperf_stop_event.set()
        h1.cmd("pkill -9 iperf || true")
        h2.cmd("pkill -9 iperf || true")
        h3.cmd("pkill -9 iperf || true")
        print("[IPERF] STOP SIGNAL SENT")

    class TrafficRequestHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/traffic/wget/start":
                start_wget_loop()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"WGET STARTED")
            elif self.path == "/traffic/wget/stop":
                stop_wget_loop()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"WGET STOPPED")
            elif self.path == "/traffic/iperf/start":
                start_iperf_loop()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"IPERF STARTED")
            elif self.path == "/traffic/iperf/stop":
                stop_iperf_loop()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"IPERF STOPPED")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            return

    def start_control_server():
        server = HTTPServer(("127.0.0.1", 9000), TrafficRequestHandler)
        print("HTTP SERVER ON 127.0.0.1:9000")
        server.serve_forever()

    threading.Thread(target=start_control_server, daemon=True).start()

    sleep(5)

    # Start the Mininet CLI, which allows interactive control of the network
    CLI( net )
    # Stop the network after exiting the CLI
    net.stop()

if __name__ == '__main__':
    # Set the log level for Mininet to display info-level messages
    setLogLevel( 'info' )
    main()