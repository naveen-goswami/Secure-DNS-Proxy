import socket
import ssl
import sys
import struct
import _thread
import os
import select
import logging

#send query to upstream server (tcp)
def sendTCP(DNSserverIP, DNSserverPort, query, caCertLocation, verifyHost):
    try:
        context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # varify that certificate belong to valid host 
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(caCertLocation)
        sock = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=verifyHost)
        sock.connect((DNSserverIP, DNSserverPort))
        sock.sendall(query)
        data = sock.recv(1024)
        if data:
        	return data
    except Exception as e:
        logger.debug(e)
    sock.close()

#send query to upstream server (udp)
def sendUDP(DNSserverIP, DNSserverPort, query):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((DNSserverIP, DNSserverPort))
        sock.sendall(query)
        data = sock.recv(1024)
        if data:
                return data
    except Exception as e:
        logger.debug(e)

#request upstream server (tcp) and write response back to client
def tcpHandler(data, addr, socket, DNSserverIP, DNSserverPort, caCertLocation, verifyHost):
    TCPanswer = sendTCP(DNSserverIP, DNSserverPort, data, caCertLocation, verifyHost)
    if TCPanswer:
    	socket.sendto(TCPanswer, addr)
    socket.shutdown(1)

# request upstream server (udp) and write response back to client 
def udpHandler(data, addr, socket, DNSserverIP, DNSserverPort):
    UDPanswer = sendUDP(DNSserverIP, DNSserverPort, data)
    if UDPanswer:
    	socket.sendto(UDPanswer, addr)

# accept and read data from client on tcp socket 
def read_tcp(tcpSock, DNSserverIP, DNSserverPort, caCertLocation, verifyHost):
    try:
        conn, addr = tcpSock.accept()
        while True:
            data = conn.recv(1024)
            if not data: break
            tcpHandler(data, addr, conn, DNSserverIP, DNSserverPort, caCertLocation, verifyHost)
    except socket.timeout as e:
        logger.info("timing out non responsive tcp connection with ", addr)
    except Exception as e:
        logger.debug(e)

# read data from the client on udp socket
def read_udp(udpSock, DNSserverIP, DNSserverPort):
    try: 
   	 data, addr = udpSock.recvfrom(1024)
   	 udpHandler(data, addr, udpSock, DNSserverIP, DNSserverPort)
    except socket.timeout: 
           logger.info("timing out non responsive udp connection with", addr)
    except Exception as e:
           logger.debug(e)


if __name__ == '__main__':
    
    logLocation = os.getenv('LOG_LOCATION', "/tmp/dns-proxy.log")
    logging.basicConfig(filename=logLocation, level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    logger=logging.getLogger(__name__)
    DNSserverIP = os.getenv('UPSTREAM_HOST', "1.1.1.1")
    DNSserverPortTCP = int(os.getenv('UPSTREAM_PORT_TCP', "853"))
    DNSserverPortUDP = int(os.getenv('UPSTREAM_PORT_UDP', "53"))
    bindInterface = os.getenv('BIND_INTERFACE', "")
    bindPort=int(os.getenv('BIND_PORT', "54"))
    verifyHost=os.getenv('VERIFY_HOST', "cloudflare-dns.com")
    caCertLocation=os.getenv('CA_CERT_LOCATION', "/etc/ssl/certs/ca-certificates.crt")
    print('Starting DNS proxy on port %d .... ' % bindPort)
    #setting up tcp socket 
    tcpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpSock.bind((bindInterface, bindPort))
    tcpSock.listen(5)
    # set tcp socket timeout out to 3 seconds
    tcpSock.settimeout(3)
    # setting up udp socket
    udpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSock.bind((bindInterface, bindPort))
    udpSock.settimeout(2)
    input = [tcpSock,udpSock]
    try: 
    	while True:
        	inputready, outputready, exceptready = select.select(input, [], [])
                # check if incoming is tcp or udp
        	for s in inputready:
                	if s == tcpSock:
                                # Start a new thread for tcp
                        	_thread.start_new_thread(read_tcp, (s, DNSserverIP, DNSserverPortTCP, caCertLocation, verifyHost))
                	elif s == udpSock:
                                # Start a new thread for udp
                        	_thread.start_new_thread(read_udp, (s, DNSserverIP, DNSserverPortUDP))
                	else:
                        	logger.debug("unknown input")
    except Exception as e:
    	logger.debug(e)
