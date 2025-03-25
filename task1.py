

import socket
import struct
import binascii


interface = "eth0"  


try:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  s.bind((interface, 0))
except socket.error as msg:
  print("Socket could not be created. Error Code : " + str(msg[0]) + " Message " + msg[1])
  exit()


def unpack_ethernet(data):
  eth_header = struct.unpack("!6s6sH", data[:14])
  dest_mac = binascii.hexlify(eth_header[0]).decode('utf-8')
  src_mac = binascii.hexlify(eth_header[1]).decode('utf-8')
  eth_protocol = eth_header[2]
  return dest_mac, src_mac, eth_protocol


def unpack_ipv4(data):
  ipv4_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
  version_ihl = ipv4_header[0]
  version = version_ihl >> 4
  ihl = version_ihl & 0xF
  ttl = ipv4_header[5]
  protocol = ipv4_header[6]
  src_ip = socket.inet_ntoa(ipv4_header[8])
  dest_ip = socket.inet_ntoa(ipv4_header[9])
  return version, ihl, ttl, protocol, src_ip, dest_ip


while True:
  packet = s.recvfrom(65565)
  data = packet[0]
  dest_mac, src_mac, eth_protocol = unpack_ethernet(data)

  print("Ethernet Frame:")
  print("Destination MAC:", dest_mac)
  print("Source MAC:", src_mac)
  print("Protocol:", eth_protocol)

  if eth_protocol == 8:  # IPv4 protocol
    version, ihl, ttl, protocol, src_ip, dest_ip = unpack_ipv4(data[14:])

    print("\nIPv4 Packet:")
    print("Version:", version)
    print("Header Length:", ihl)
    print("TTL:", ttl)
    print("Protocol:", protocol)
    print("Source IP:", src_ip)
    print("Destination IP:", dest_ip)

  print("\n-------------------------------------\n")


import socket
import struct
import binascii


interface = "eth0"  


try:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  s.bind((interface, 0))
except socket.error as msg:
  print("Socket could not be created. Error Code : " + str(msg[0]) + " Message " + msg[1])
  exit()


def unpack_ethernet(data):
  eth_header = struct.unpack("!6s6sH", data[:14])
  dest_mac = binascii.hexlify(eth_header[0]).decode('utf-8')
  src_mac = binascii.hexlify(eth_header[1]).decode('utf-8')
  eth_protocol = eth_header[2]
  return dest_mac, src_mac, eth_protocol


def unpack_ipv4(data):
  ipv4_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
  version_ihl = ipv4_header[0]
  version = version_ihl >> 4
  ihl = version_ihl & 0xF
  ttl = ipv4_header[5]
  protocol = ipv4_header[6]
  src_ip = socket.inet_ntoa(ipv4_header[8])
  dest_ip = socket.inet_ntoa(ipv4_header[9])
  return version, ihl, ttl, protocol, src_ip, dest_ip


while True:
  packet = s.recvfrom(65565)
  data = packet[0]
  dest_mac, src_mac, eth_protocol = unpack_ethernet(data)

  print("Ethernet Frame:")
  print("Destination MAC:", dest_mac)
  print("Source MAC:", src_mac)
  print("Protocol:", eth_protocol)

  if eth_protocol == 8:  # IPv4 protocol
    version, ihl, ttl, protocol, src_ip, dest_ip = unpack_ipv4(data[14:])

    print("\nIPv4 Packet:")
    print("Version:", version)
    print("Header Length:", ihl)
    print("TTL:", ttl)
    print("Protocol:", protocol)
    print("Source IP:", src_ip)
    print("Destination IP:", dest_ip)

  print("\n-------------------------------------\n")
