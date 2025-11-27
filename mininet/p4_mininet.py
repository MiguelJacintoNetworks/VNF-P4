import os
import tempfile
from sys import exit
from time import sleep

from mininet.log import debug, error, info
from mininet.moduledeps import pathCheck
from mininet.node import Host, Switch
from netstat import check_listening_on_port

SWITCH_START_TIMEOUT = 10

class P4Host(Host):
    def config(self, **params):
        result = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return result

    def describe(self):
        print("**********")
        print(self.name)
        print(
            "DEFAULT INTERFACE: %s\t%s\t%s"
            % (
                self.defaultIntf().name,
                self.defaultIntf().IP(),
                self.defaultIntf().MAC(),
            )
        )
        print("**********")

class P4Switch(Switch):
    device_id = 0

    def __init__(
        self,
        name,
        sw_path = None,
        json_path = None,
        thrift_port = None,
        pcap_dump = False,
        log_console = False,
        log_file = None,
        verbose = False,
        device_id = None,
        enable_debugger = False,
        **kwargs,
    ):
        Switch.__init__(self, name, **kwargs)

        assert sw_path
        assert json_path

        pathCheck(sw_path)

        if not os.path.isfile(json_path):
            error("INVALID JSON FILE\n")
            exit(1)

        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose

        logfile = "/tmp/p4s.%s.log" % self.name
        self.output = open(logfile, "w")

        self.thrift_port = thrift_port

        if check_listening_on_port(self.thrift_port):
            error(
                "%s CANNOT BIND PORT %d BECAUSE IT IS BOUND BY ANOTHER PROCESS\n"
                % (self.name, self.grpc_port)
            )
            exit(1)

        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console

        if log_file is not None:
            self.log_file = log_file
        else:
            self.log_file = "/tmp/p4s.%s.log" % self.name

        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1

        self.nanomsg = "ipc:///tmp/bm-%s-log.ipc" % self.device_id

    @classmethod
    def setup(cls):
        pass

    def check_switch_started(self, pid):
        while True:
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            if check_listening_on_port(self.thrift_port):
                return True
            sleep(0.5)

    def start(self, controllers):
        info("STARTING P4 SWITCH %s.\n" % self.name)

        args = [self.sw_path]

        for port, intf in list(self.intfs.items()):
            if not intf.IP():
                args.extend(["-i", "%s@%s" % (port, intf.name)])

        if self.pcap_dump:
            args.append("--pcap %s" % self.pcap_dump)

        if self.thrift_port:
            args.extend(["--thrift-port", str(self.thrift_port)])

        if self.nanomsg:
            args.extend(["--nanolog", self.nanomsg])

        args.extend(["--device-id", str(self.device_id)])
        P4Switch.device_id += 1

        args.append(self.json_path)

        if self.enable_debugger:
            args.append("--debugger")

        if self.log_console:
            args.append("--log-console")

        info(" ".join(args) + "\n")

        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        pid = None
        with tempfile.NamedTemporaryFile() as tmp:
            self.cmd(
                " ".join(args)
                + " >"
                + self.log_file
                + " 2>&1 & echo $! >> "
                + tmp.name
            )
            pid = int(tmp.read())

        debug("P4 SWITCH %s PID IS %s.\n" % (self.name, pid))

        if not self.check_switch_started(pid):
            error("P4 SWITCH %s DID NOT START CORRECTLY.\n" % self.name)
            exit(1)

        info("P4 SWITCH %s HAS BEEN STARTED.\n" % self.name)

    def stop(self):
        self.output.flush()
        self.cmd("KILL %s" % self.sw_path)
        self.cmd("WAIT")
        self.deleteIntfs()

    def attach(self, intf):
        assert 0

    def detach(self, intf):
        assert 0