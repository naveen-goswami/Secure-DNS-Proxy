#/bin/bash
sudo docker run   -t -i -e UPSTREAM_HOST='1.1.1.1' \
-e UPSTREAM_PORT_TCP='853' \
-e UPSTREAM_PORT_UDP='53' \
-e PYTHONUNBUFFERED=0 \
-e logLocation='/tmp/dns-proxy.log'
-e BIND_INTERFACE='' \
-e BIND_PORT='54' \
-e VERIFY_HOST='cloudflare-dns.com' \
-e CA_CERT_LOCATION='/etc/ssl/certs/ca-certificates.crt' \
-p 53:53 \
-p 53:53/udp \
--name dns-proxy dns-proxy:latest

