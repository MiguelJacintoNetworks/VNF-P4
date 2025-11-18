import argparse
import os

def run_iperf_test(host, server_ip, protocol):
    print(f"Running {protocol} test from {host.name} to {server_ip}...")
    if protocol == "tcp":
        host.cmd(f"iperf3 -c {server_ip} -t 10")
    elif protocol == "udp":
        host.cmd(f"iperf3 -c {server_ip} -u -b 10M -t 10")
    print(f"Finished {protocol} test from {host.name} to {server_ip}.")

"""
This script is meant to be run within the Mininet CLI or a similar environment
where h1, h2, h3, h4 are Mininet host objects.
For standalone execution, you would need to mock these objects or integrate with Mininet directly.
"""
def main(h1, h2, h3, h4):
    # Setup cmdline arguments
    parser = argparse.ArgumentParser(description="Network performance tester using iperf3")
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp"], default="tcp",
                        help="Specify the protocol for iperf3 test (tcp or udp)")
    args = parser.parse_args()

    # Start iperf3 server on h4
    server_ip = h4.IP()
    print(f"Starting iperf3 server on {h4.name}...")
    h4.cmd("iperf3 -s -D") # -D runs in daemon mode
    os.system("sleep 1") # wait for server to start

    # Run tests
    run_iperf_test(h1, server_ip, args.protocol)
    run_iperf_test(h2, server_ip, args.protocol)
    run_iperf_test(h3, server_ip, args.protocol)
    os.system("sleep 10") # wait for tests to finish

    # Stop iperf3 server on h4 (optional, can be done manually or after all tests)
    h4.cmd("killall -q iperf3")
    print(f"Stopped iperf3 server on {h4.name}.")

"""
MockHost class is used to mock the host objects for standalone execution.
"""
if __name__ == "__main__":
    class MockHost:
        def __init__(self, name):
            self.name = name
        def cmd(self, command):
            print(f"Executing on {self.name}: {command}")

    h1_mock = MockHost('h1')
    h2_mock = MockHost('h2')
    h3_mock = MockHost('h3')
    h4_mock = MockHost('h4')
    main(h1_mock, h2_mock, h3_mock, h4_mock)
