from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

def run_iptables(cmd_list):
    try:
        out = subprocess.check_output(cmd_list, stderr=subprocess.STDOUT)
        return out.decode(), 0
    except subprocess.CalledProcessError as e:
        return e.output.decode(), e.returncode

@app.route("/health")
def health():
    return jsonify({"status": "ok", "role": "vfw"}), 200

@app.route("/rules", methods=["GET"])
def list_rules():
    out, rc = run_iptables(["iptables", "-L", "-v", "-n"])
    return jsonify({"rc": rc, "output": out})

@app.route("/rules", methods=["POST"])
def add_rule():
    data = request.json or {}
    # exemplo muito simples:
    # { "action": "DROP", "proto": "tcp", "dport": 80, "dst": "10.0.2.2" }
    proto = data.get("proto", "tcp")
    dport = str(data.get("dport", 80))
    dst = data.get("dst", None)
    base_cmd = ["iptables", "-A", "FORWARD", "-p", proto, "--dport", dport]
    if dst:
        base_cmd += ["-d", dst]
    base_cmd += ["-j", data.get("action", "DROP")]
    out, rc = run_iptables(base_cmd)
    return jsonify({"rc": rc, "cmd": " ".join(base_cmd), "output": out})

if __name__ == "__main__":
    # podes também aqui pôr as políticas base (ACCEPT, RELATED, etc.)
    app.run(host="0.0.0.0", port=5001)
