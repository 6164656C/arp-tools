import struct
import sys
import time
from ctypes import *
import socket
import fcntl
import ctypes
import getopt
import ipaddress

IFNAMSIZ = 16

ifname = None
req_dst_ip = None

class arp_packet(ctypes.Structure):
    _fields_ = [
        ("htype", ctypes.c_ushort),
        ("ptype", ctypes.c_ushort),
        ("hlen", ctypes.c_ubyte),
        ("plen", ctypes.c_ubyte),
        ("oper", ctypes.c_ushort),
        ("srcmac", ctypes.c_ubyte * 6),
        ("srcip", ctypes.c_ubyte * 4),
        ("dstmac", ctypes.c_ubyte * 6),
        ("dstip", ctypes.c_ubyte * 4)
    ]
    def __new__(cls, buffer):
        return cls.from_buffer_copy(buffer)
    def __init__(self, buffer):
        self.buffer = buffer

class sockaddr(ctypes.Structure):
    _fields_ = [
        ("sa_family", ctypes.c_ushort),
        ("sa_data", (ctypes.c_ubyte * 14)),
    ]

class ifmap(ctypes.Structure):
    _fields_ = [
        ("mem_start", ctypes.c_ulong),
        ("mem_end", ctypes.c_ulong),
        ("base_addr", ctypes.c_ushort),
        ("irq", ctypes.c_ubyte),
        ("dma", ctypes.c_ubyte),
        ("port", ctypes.c_ubyte),
        ("pad", ctypes.c_ubyte * 3),
    ]

class ifreq_union(ctypes.Union):
    _fields_ = [
        ("ifr_addr", sockaddr),
        ("ifr_dstaddr", sockaddr),
        ("ifr_broadaddr", sockaddr),
        ("ifr_netmask", sockaddr),
        ("ifr_hwaddr", sockaddr),
        ("ifr_flags", ctypes.c_short),
        ("ifr_ifindex", ctypes.c_int),
        ("ifr_metric", ctypes.c_int),
        ("ifr_mtu", ctypes.c_int),
        ("ifr_map", ifmap),
        ("ifr_slave", ctypes.c_char * IFNAMSIZ),
        ("ifr_newname", ctypes.c_char * IFNAMSIZ),
        ("ifr_data", ctypes.c_char_p),
    ]

class ifreq(ctypes.Structure):
    _anonymous_ = ("_union",)
    _fields_ = [
        ("ifr_name", ctypes.c_char * IFNAMSIZ),
        ("_union", ifreq_union),
    ]

# Define ioctl constants (from Linux/if.h)
SIOCGIFHWADDR  = 0x8927  # Get hardware address
SIOCGIFADDR    = 0x8915  # Get IP address
SIOCGIFBRDADDR = 0x8919
SIOCGIFNETMASK = 0x891B

def crc32(data: bytes) -> str:
    crc_table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320  # CRC32 polynomial
            else:
                crc >>= 1
        crc_table.append(crc)

    # Initialize CRC value
    crc = 0xFFFFFFFF
    for byte in data:
        lookup_index = (crc ^ byte) & 0xFF
        crc = (crc >> 8) ^ crc_table[lookup_index]

    # Finalize the CRC value by inverting the bits
    crc ^= 0xFFFFFFFF
    return f"{(crc & 0xFFFFFFFF):08x}"

def get_ip_address(ifname:str):
    ifr = ifreq()
    ifr.ifr_name = ifname.encode() + b'\x00' * (IFNAMSIZ - len(ifname))
    fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifr)
    return ifr.ifr_addr.sa_data[2:6]

def get_nm_address(ifname:str):
    ifr = ifreq()
    ifr.ifr_name = ifname.encode() + b'\x00' * (IFNAMSIZ - len(ifname))
    fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, ifr)
    return ifr.ifr_addr.sa_data[2:6]

def get_hw_address(ifname:str):
    ifr = ifreq()
    ifr.ifr_name = ifname.encode() + b'\x00' * (IFNAMSIZ - len(ifname))
    fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifr)
    return ifr.ifr_hwaddr.sa_data[0:6]

class Ethernet(Structure):
    _fields_ = [
        ("D_MAC", c_ubyte, 6),
        ("S_MAC", c_ubyte, 6),
        ("EtherType", c_ubyte, 2) # 0x0806 for ARP and 0x0800 for IPv4
    ]

#socket.setdefaulttimeout(3)
try:
    opts, args = getopt.getopt(sys.argv[1:], "hi:t:", ["ifname=", "target=","help"])
    if len(sys.argv[1:]) == 0:
        print("sudo arp.py -i interface -t ip")
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print ("sudo arp.py -i interface -t ip")
            sys.exit(2)
        elif opt in ("-i", "--ifname"):
            ifname = arg
        elif opt in ("-t", "--target"):
            req_dst_ip = arg
except getopt.GetoptError:
    print("sudo arp.py -i interface -t ip")
    sys.exit(2)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
s.bind((ifname, socket.SOCK_RAW))

if ifname and not req_dst_ip:
    iip = ".".join(str(quartet) for quartet in get_ip_address(ifname))
    inm = ".".join(str(quartet) for quartet in get_nm_address(ifname))
    print(f"interface {ifname}  {iip}/{inm}")
    try:
        network = ipaddress.ip_network(f"{iip}/{inm}", strict=False)
        # lower_ip = str(network.network_address)
        # upper_ip = str(network.broadcast_address)
        # print(f"interface {ifname}  {upper_ip}/{lower_ip}")
    except ValueError:
        print(f"Error: Invalid IP address or network mask: {iip}/{inm}")
        sys.exit(2)
    # count = 0
    # for i in range(4):
    #     part = inm[i]
    #     if 255 - inm[i] != 0:
    #         count += (255-inm[i]) * 256**(3-i)
    # print(f"the number of host {count}")
    #sys.exit(2)

macsrc = get_hw_address(ifname)
ethernet = struct.pack('!6B', *(0xFF,) * 6)
ethernet += struct.pack("!6B", macsrc[0], macsrc[1],macsrc[2], macsrc[3],macsrc[4], macsrc[5])
ethernet += struct.pack('!H', 0x0806)
ethernet += struct.pack('!HHBBH', 0x0001, 0x0800, 0x06, 0x04,0x0001)

for b in macsrc:
    ethernet += struct.pack('!B',b)

req_src_ip = get_ip_address(ifname)

print(req_src_ip)

for b in req_src_ip:
    ethernet += struct.pack("!B",b)

ethernet += struct.pack('!6B',*(0x00,) * 6)

for x in req_dst_ip.split('.'):
    ethernet += struct.pack("!B",int(x))
print(f"socket initialized on {ifname}:{macsrc}/{req_src_ip} targetting {req_dst_ip}")
try:
    while True:
        s.send(ethernet)
        stime = time.time_ns()
        buff = s.recv(65535)
        eth_header = struct.unpack('!6s6s2s', buff[:14])
        if eth_header[2].hex() == "0806":  # 0X0806: ETHTYPE is ARP
            arp_p = arp_packet(buff[14:14 + 28])
            srcmac = ":".join(format(b, 'x') for b in arp_p.srcmac)
            res_src_ip = ".".join(str(b) for b in arp_p.srcip)
            dstmac = ":".join(format(b, 'x') for b in arp_p.dstmac)
            res_dst_ip = ".".join(str(b) for b in arp_p.dstip)
            if req_dst_ip == res_src_ip and res_dst_ip == '.'.join(str(b) for b in req_src_ip) and socket.ntohs(arp_p.oper) == 0x0002: # oper == 0x0002 is ARP response
                etime = time.time_ns()
                print(f"response from {srcmac} ({res_src_ip}): time={round((etime - stime)/1000, 3)} usec")
            time.sleep(1)
except KeyboardInterrupt:
    pass
s.close()
