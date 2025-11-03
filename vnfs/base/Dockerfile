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
 && apt clean \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
 
ENTRYPOINT ["/entrypoint.sh"]