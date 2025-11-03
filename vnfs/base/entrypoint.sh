#!/bin/bash
# Entrypoint genérico para todas as VNFs base
# Mantém o container ativo para execuções interativas
echo "[INFO] Container $(hostname) iniciado."
echo "[INFO] Interfaces disponíveis:"
ip link show
echo "[INFO] A dormir indefinidamente..."
sleep infinity