from flask import Flask, jsonify, request
from prometheus_client import generate_latest, Counter, CONTENT_TYPE_LATEST

app = Flask(__name__)

# métrica simples
PACKETS_SEEN = Counter('vmon_packets_seen', 'Packets seen by vMonitor')

@app.route("/health")
def health():
    return jsonify({"status": "ok", "role": "vmon"}), 200

@app.route("/metrics")
def metrics():
    # se tiveres um script que incrementa PACKETS_SEEN, isto já sai no formato Prometheus
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route("/config", methods=["POST"])
def config():
    data = request.json or {}
    # aqui podes receber "interfaces": ["vmon-eth0", "vmon-eth1"], "filter": "tcp"
    # por agora só confirma
    return jsonify({"status": "accepted", "received": data}), 200

if __name__ == "__main__":
    # escuta em todas as interfaces
    app.run(host="0.0.0.0", port=5000)
