#!/usr/bin/env python3
from socket import *
import struct
import binascii

# Faz desempacotamento dados do frame ethernet que nos chegam em formato de bytes 
def ethernet_frame(raw_dados):
    mac_destino, mac_fonte, tipo_ethernet = struct.unpack('! 6s 6s H', raw_dados[:14])

    return byte_to_hex_mac(mac_destino), byte_to_hex_mac(mac_fonte), htons(tipo_ethernet), raw_dados[14:]

# Passa o endereço da função MAC na função ethernet_frame para hexadecimal
# Acabando por ser representado numa arquitetura de 6 octetos
def byte_to_hex_mac(mac_em_bytes):
    endereco = binascii.hexlify(mac_em_bytes).decode("ascii")
    return ":".join([endereco[i:i+2] for i in range(0,12,2)])


# Extrai dados do header, pacote ARP (Request/ Reply)
def header_pacote_arp(payload):
    (tipo_hardware, tipo_protocolo, tamanho_endereco_hardware,
     tamanho_endereco_protocolo, operacao, mac_sender, ip_sender,
     mac_dest, ip_dest) = struct.unpack("!HHBBH6s4s6s4s", payload)

    # Dicionário tipo_de_operacao
    """
     Este dicionario indica que tipo de operação é realizada
      é usado no diconaŕio a seguir(dados_header_arp), onde é passado o valor da variável
      operacao que é passado como key
     """

    # tipo_de_operacao = {1:"(1) Request", 2:'(2) Reply'}
    if ip_sender == "192.168.15.108":
      dados_header_arp = {"ERROR": "ARP gratuito"}
    else:
      dados_header_arp = {'Operação': operacao, 'MAC de quem envia o reply': byte_to_hex_mac(mac_sender),
                          'Ip de quem envia o reply':inet_ntoa(ip_sender)}

    return dados_header_arp