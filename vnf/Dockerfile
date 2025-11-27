FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    iptables \
    ipvsadm \
    net-tools \
    ethtool \
    tcpdump \
    curl \
    vim \
    iperf3 \
    procps \
    python3 \
    python3-pip \
 && apt clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install flask prometheus_client scapy

COPY entrypoint.sh /entrypoint.sh
COPY vmon.py /vmon.py
COPY vlb.py /vlb.py

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]