from flask import Flask, request, jsonify
app = Flask(__name__)

# lista de backends que o controller pode alterar
BACKENDS = [
    {"name": "path1", "next_hop": "10.0.10.2"},
    {"name": "path2", "next_hop": "10.0.10.3"}
]
rr_index = 0

@app.route("/health")
def health():
    return jsonify({"status": "ok", "role": "vlb"}), 200

@app.route("/backends", methods=["GET"])
def list_backends():
    return jsonify(BACKENDS)

@app.route("/backends", methods=["POST"])
def set_backends():
    global BACKENDS, rr_index
    data = request.json or []
    BACKENDS = data
    rr_index = 0
    return jsonify({"status": "updated", "count": len(BACKENDS)})

@app.route("/next", methods=["GET"])
def next_backend():
    global rr_index
    if not BACKENDS:
        return jsonify({"error": "no backends"}), 404
    b = BACKENDS[rr_index % len(BACKENDS)]
    rr_index += 1
    return jsonify(b)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
