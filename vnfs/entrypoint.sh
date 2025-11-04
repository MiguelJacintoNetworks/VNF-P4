#!/bin/bash
# Entrypoint genérico para todas as VNFs base

echo "[INFO] Container $(hostname) iniciado."
echo "[INFO] Interfaces disponíveis:"
ip link show

case "$HOSTNAME" in
  mn.vmon|vmon)
    echo "[INFO] Arrancando vMonitor (Flask em 0.0.0.0:5000)..."
    python3 /opt/vmon.py &
    ;;
  mn.vfw|vfw)
    echo "[INFO] Arrancando vFirewall (iptables + Flask em 0.0.0.0:5001)..."

    # políticas base
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -p icmp -j ACCEPT

    python3 /opt/vfw.py &
    ;;
  mn.vlb|vlb)
    echo "[INFO] Arrancando vLoadBalancer (Flask em 0.0.0.0:5002)..."
    python3 /opt/vlb.py &
    ;;
  *)
    echo "[WARN] Nome de container '$HOSTNAME' não tem papel definido."
    ;;
esac

echo "[INFO] A dormir indefinidamente..."
sleep infinity
