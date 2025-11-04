#!/usr/bin/env python3
import docker

# Inicializa cliente Docker
client = docker.from_env()

def _resolve_container(name: str):
    """
    Tenta obter o container pelo nome exato.
    Se não existir, tenta com prefixo 'mn.' (padrão do Containernet).
    """
    # tenta exatamente como veio
    try:
        return client.containers.get(name)
    except docker.errors.NotFound:
        pass

    # tenta com prefixo mn.
    if not name.startswith("mn."):
        alt_name = f"mn.{name}"
        try:
            return client.containers.get(alt_name)
        except docker.errors.NotFound:
            pass

    return None


def list_vnfs():
    """
    Lista todos os containers VNFs ativos (mn.* ou imagens que contenham 'vnf').
    """
    containers = client.containers.list(all=True)
    vnf_list = []
    for c in containers:
        # aceita ambos: mn.vfw / mn.vmon / mn.vlb e imagens com 'vnf'
        if c.name.startswith("mn.") or (c.image.tags and any("vnf" in t for t in c.image.tags)):
            vnf_list.append({
                "name": c.name,
                "status": c.status,
                "image": c.image.tags[0] if c.image.tags else "unknown"
            })
    return vnf_list


def exec_in_vnf(name, cmd):
    """
    Executa um comando dentro de um container VNF.
    Aceita 'mn.vfw' e também 'vfw'.
    """
    try:
        container = _resolve_container(name)
        if container is None:
            return f"❌ Container '{name}' não encontrado (nem como 'mn.{name}')."
        result = container.exec_run(cmd)
        output = result.output.decode('utf-8', errors='ignore')
        return output.strip()
    except Exception as e:
        return f"⚠️ Erro ao executar comando em {name}: {e}"


def restart_vnf(name):
    container = _resolve_container(name)
    if container is None:
        return f"❌ Container '{name}' não encontrado (nem como 'mn.{name}')."
    container.restart()
    return f"🔄 VNF {container.name} reiniciada com sucesso."


def get_logs(name, tail=20):
    container = _resolve_container(name)
    if container is None:
        return f"❌ Container '{name}' não encontrado (nem como 'mn.{name}')."
    logs = container.logs(tail=tail).decode('utf-8', errors='ignore')
    return logs
