import socket
import struct
import binascii

def arp_request():
	sock_envia = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
	sock_envia.bind(("wlp1s0",socket.htons(0x0806)))

	mac_fonte = '98:83:89:5e:41:91'                                                    
	ip_fonte = '192.168.15.108'                                          
	mac_dest = 'ff:ff:ff:ff:ff:ff'
	ip_dest = '192.168.15.1'
	i = 1

	while i <= 254:
		#try:
		ip_dest_lista = ip_dest.split(".")
		ip_final = int(ip_dest_lista[3])

		tipo_hardware = 1 # especificar que o endereço de hardware é um endereço MAC Ethernet
		tipo_protocolo = 0x0800 # Ipv4
		len_hardware = 6            
		len_protocolo = 4         
		operacao = 1 # 1 <= request ou 2 <= reply                                              

		src_ip = socket.inet_aton(ip_fonte)
		dest_ip = socket.inet_aton(ip_dest)

		mac_dest_byte_order = binascii.unhexlify(mac_dest.replace(":", ""))
		mac_src_byte_order = binascii.unhexlify(mac_fonte.replace(":", ""))

		# Ethernet frame
		protocolo = 0x0806                                                 
		ethernet_frame = struct.pack("!6s6sH", mac_dest_byte_order, mac_src_byte_order, protocolo)

		arp_header = struct.pack("!HHBBH6s4s6s4s",tipo_hardware, 
									tipo_protocolo, 
									len_hardware, 
									len_protocolo, 
									operacao, 
									mac_src_byte_order, 
									src_ip, 
									mac_dest_byte_order, 
									dest_ip)

		pacote = ethernet_frame + arp_header

		sock_envia.send(pacote) # envia o request
		ip_final += 1
		i += 1
		
		if ip_final == 108:
			ip_final += 1
			ip_dest_lista[3] = str(ip_final)
			ip_dest = ".".join(ip_dest_lista)
		else:
			ip_dest_lista[3] = str(ip_final)
			ip_dest = ".".join(ip_dest_lista)