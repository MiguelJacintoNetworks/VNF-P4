FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    iptables \
    net-tools \
    tcpdump \
    curl \
    vim \
    iperf3 \
    procps \
    python3 \
    python3-pip \
 && apt clean \
 && rm -rf /var/lib/apt/lists/*

# libs python para API e métricas
RUN pip3 install flask prometheus_client

# copia o entrypoint e os scripts das VNFs
COPY entrypoint.sh /entrypoint.sh
COPY vmon.py /opt/vmon.py
COPY vfw.py  /opt/vfw.py
COPY vlb.py  /opt/vlb.py

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]