# P4:

# COMPILE

p4c-bm2-ss --std p4-16  p4/l3switch_mslp.p4 -o json/l3switch_mslp.json  --p4runtime-files json/l3switch_mslp.p4info.txt

p4c-bm2-ss --std p4-16  p4/l3switch_mslp_firewall.p4 -o json/l3switch_mslp_firewall.json  --p4runtime-files json/l3switch_mslp_firewall.p4info.txt

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
sudo docker build -t vnf .

# MININET:

# RUN:
sudo PYTHONPATH=$PYTHONPATH:/home/netsim/containernet python3 tp-topo.py
sudo python3 mininet/tp-topo.py

# Parar Tudo:
sudo mn -c

h1 python3 -m http.server 80 &
h4 curl -v http://10.0.1.1:80/

r1 simple_switch_CLI --thrift-port 9091

vlb ethtool -K vlb-eth0 rx off tx off tso off gso off gro off