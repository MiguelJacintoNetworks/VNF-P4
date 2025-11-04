# P4:

# COMPILE

p4c-bm2-ss --std p4-16  p4/l3switch_mslp.p4 -o configs/json/l3switch_mslp.json  --p4runtime-files configs/p4info/l3switch_mslp.p4info.txt

p4c-bm2-ss --std p4-16  p4/l3switch_mslp_firewall.p4 -o configs/json/l3switch_mslp_firewall.json  --p4runtime-files configs/p4info/l3switch_mslp_firewall.p4info.txt

# CONTROLLER:
python3 controller/tp-controller.py   --config configs/switches_config.json   --programs configs/switches_programs.json   --tunnels configs/tunnels_config.json   --clone configs/clone_config.json

# DOCKER:

# Ver Imagens:
sudo docker image ls

# Ver Containers
sudo docker ps -a

# Apagar Containers:
sudo docker rm -f mn.vlb mn.vmon mn.vfw 2>/dev/null

# Apagar Imagens:
sudo docker rmi alpine:latest

# Construir Imagem a Partir do DockerFile:
sudo docker build -t vnf-base .

# MININET:

# RUN:
sudo PYTHONPATH=$PYTHONPATH:/home/netsim/containernet python3 tp-topo.py

# Parar Tudo:
sudo mn -c
