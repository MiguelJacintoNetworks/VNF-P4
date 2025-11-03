Docker:

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

MININET:

# Parar Tudo:
sudo mn -c
