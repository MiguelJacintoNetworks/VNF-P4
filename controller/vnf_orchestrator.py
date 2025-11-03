#!/usr/bin/env python3
"""
vnf_orchestrator.py
Módulo auxiliar para gerir VNFs em Containernet/Docker a partir do controller.
"""

import docker
import subprocess

# Inicializa cliente Docker
client = docker.from_env()


def list_vnfs():
    """
    Lista todos os containers VNFs ativos (mn.* ou vnf-base).
    """
    containers = client.containers.list(all=True)
    vnf_list = []
    for c in containers:
        if c.name.startswith("mn.") or "vnf" in c.image.tags[0]:
            vnf_list.append({
                "name": c.name,
                "status": c.status,
                "image": c.image.tags[0] if c.image.tags else "unknown"
            })
    return vnf_list


def exec_in_vnf(name, cmd):
    """
    Executa um comando dentro de um container VNF (por exemplo iptables -L).
    """
    try:
        container = client.containers.get(name)
        result = container.exec_run(cmd)
        output = result.output.decode('utf-8')
        return output.strip()
    except docker.errors.NotFound:
        return f"❌ Container '{name}' não encontrado."
    except Exception as e:
        return f"⚠️ Erro ao executar comando em {name}: {e}"


def restart_vnf(name):
    """
    Reinicia uma VNF existente (sem a remover).
    """
    try:
        container = client.containers.get(name)
        container.restart()
        return f"🔄 VNF {name} reiniciada com sucesso."
    except docker.errors.NotFound:
        return f"❌ Container '{name}' não encontrado."
    except Exception as e:
        return f"⚠️ Erro ao reiniciar {name}: {e}"


def get_logs(name, tail=20):
    """
    Mostra as últimas linhas de log do container.
    """
    try:
        container = client.containers.get(name)
        logs = container.logs(tail=tail).decode('utf-8')
        return logs
    except docker.errors.NotFound:
        return f"❌ Container '{name}' não encontrado."
    except Exception as e:
        return f"⚠️ Erro ao obter logs de {name}: {e}"
