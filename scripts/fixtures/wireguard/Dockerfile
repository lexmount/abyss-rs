FROM alpine:3.22
RUN apk add --no-cache wireguard-tools iproute2 iptables dnsmasq python3
COPY peer.py /peer.py
ENTRYPOINT ["python3", "-u", "/peer.py"]
