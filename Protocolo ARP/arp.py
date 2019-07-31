import socket
import struct
import reply as rp
import request as rq

rq.arp_request()
sock_recebe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:	
	sock_recebe.settimeout(4)
	try:
		raw_dados, addr = sock_recebe.recvfrom(65536)
	except socket.error:
		print("Error timeout")
		break

	mac_destino, mac_fonte, tipo_ethernet, payload  = rp.ethernet_frame(raw_dados)
	header = rp.header_pacote_arp(payload[:28])

	if tipo_ethernet == 1544 and header['Operação'] == 2:
		print("##### HEADER ARP #####")
		print("\n".join("{}: {}\n".format(key, valor_key) for key, valor_key in header.items()))
