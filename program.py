import struct
import socket
import random
import string
import argparse
import os
import subprocess
import time


class IPHeader:

    def __init__(self, src='127.0.0.7', dst='127.0.0.2'):
        self.dst = dst
        self.src = src
        self.raw = None
        self.create_ipv4_feilds()

    def pack_ipv4_feilds(self):
        self.raw = struct.pack('!BBHHHBBH4s4s',
                               self.ip_ver,  # IP Version
                               self.ip_dfc,  # Differentiate Service Feild
                               self.ip_tol,  # Total Length
                               self.ip_idf,  # Identification
                               self.ip_flg,  # Flags
                               self.ip_ttl,  # Time to leave
                               self.ip_proto,  # protocol
                               self.ip_chk,  # Checksum
                               self.ip_saddr,  # Source IP
                               self.ip_daddr  # Destination IP
                               )
        return self.raw

    def create_ipv4_feilds(self):
        # ---- [Internet Protocol Version] ----
        ip_ver = 4
        ip_vhl = 5

        self.ip_ver = (ip_ver << 4) + ip_vhl

        # ---- [ Differentiate Service Field ]
        ip_dsc = 0
        ip_ecn = 0

        self.ip_dfc = (ip_dsc << 2) + ip_ecn

        # ---- [ Total Length]
        self.ip_tol = 0

        # ---- [ Identification ]
        self.ip_idf = 58766

        # ---- [ Flags ]
        ip_rsv = 0
        ip_dtf = 0
        ip_mrf = 0
        ip_frag_offset = 0

        self.ip_flg = (ip_rsv << 7) + (ip_dtf << 6) + (ip_mrf << 5) + (ip_frag_offset)

        # ---- [ Total Length ]
        self.ip_ttl = 64

        # ---- [ Protocol ]
        self.ip_proto = socket.IPPROTO_UDP

        # ---- [ Check Sum ]
        self.ip_chk = 0

        # ---- [ Source Address ]
        self.ip_saddr = socket.inet_aton(self.src)

        # ---- [ Destination Address ]
        self.ip_daddr = socket.inet_aton(self.dst)

        return


class UDPHeader:

    def __init__(self, udp_source=0, udp_dest=0):
        self.udp_source = udp_source  # source port
        self.udp_dest = udp_dest  # destination port
        self.raw = None
        self.create_udp_feilds()

    def pack_udp_feilds(self):
        self.raw = struct.pack('!HHHH',
                               self.udp_source,  # Source port
                               self.udp_dest,  # Destination port
                               self.udp_len,
                               self.udp_check,
                               )
        return self.raw

    def create_udp_feilds(self):
        self.udp_len = 8
        # ---- [ Checksum ]
        self.udp_check = 0
        return


def sniffer(data):
    packet = struct.unpack('!BBHHHBBH4s4sHHHH', data[:28])
    fields = {"Differ_Service": packet[1],
              "Total_length": packet[2],
              "ID": packet[3],
              "Flags": packet[4],
              "Time_to_live": packet[5],
              "Protocol": packet[6],
              "IP_Checksum": packet[7],
              "Source_IP": '.'.join(str(i) for i in struct.unpack('BBBB', packet[8])),
              "Dest_IP": '.'.join(str(i) for i in struct.unpack('BBBB', packet[9])),
              "Source_port": packet[10],
              "Dest_port": packet[11],
              "Udp_length": packet[12],
              "UDP_Checksum": packet[13],
              "Data": data[28:].decode('UTF-8'),
              }
    return fields


class Host:

    def __init__(self, ip_addr, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.ip_address = ip_addr
        self.port = port
        self.socket.bind((self.ip_address, self.port))

    # --------------Client ---------
    def request(self, ip_addr, port):
        data = b'kdsjhvlbvs'
        ip = IPHeader(dst=ip_addr, src=self.ip_address)
        udp = UDPHeader(udp_dest=port, udp_source=self.port)
        udp.udp_len = len(data) + 8
        udp.pack_udp_feilds()
        ip.ip_dfc = 8
        ip.pack_ipv4_feilds()
        self.socket.sendto(ip.raw + udp.raw + data, (ip_addr, port))

    def recv_message_by_ttl_field(self):
        message = []
        while True:
            data = sniffer(self.socket.recv(1024))
            message.append(data['Time_to_live'])
            if data["Differ_Service"] != 10:
                break
        return bytes(message)

    def recv_message_by_id_field(self):
        message = b''
        while True:
            data = sniffer(self.socket.recv(1024))
            message += struct.pack('H', data['ID'])
            if data["Differ_Service"] != 10:
                break
        return message

    def recv_message_by_packet_len(self):
        message = ''
        while True:
            data = sniffer(self.socket.recv(1024))
            if data['Total_length'] < 70:
                message += '0'
            elif data['Total_length'] > 70:
                message += '1'
            if data["Differ_Service"] != 10:
                break
        return bytes([int(message[8 * i:8 * (i+1)], 2) for i in range(len(message)//8)])
    # ----------------------Server ---------------

    def recv(self):
        while True:
            data = sniffer(self.socket.recv(1024))
            if data['Differ_Service'] == 8:
                return data['Source_IP'], data['Source_port']

    def send_message_by_ttl_field(self, message, dst_ip, dst_port):
        ip_header = IPHeader(self.ip_address, dst_ip)
        udp_header = UDPHeader(self.port, dst_port)
        for i in range(len(message)):
            data_len = random.randint(40, 50)
            data_ = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(data_len)). \
                encode()
            udp_header.udp_len = len(data_) + 8
            udp_header.pack_udp_feilds()
            ip_header.ip_ttl = message[i]
            ip_header.ip_idf = random.randint(10000, 65000)
            if i == len(message) - 1:
                ip_header.ip_dfc = 0
            else:
                ip_header.ip_dfc = 10
            ip_header.pack_ipv4_feilds()
            self.socket.sendto(ip_header.raw + udp_header.raw + data_, (dst_ip, dst_port))
        return

    def send_message_by_id_field(self, message, dst_addr, dst_port):
        ip_header = IPHeader(self.ip_address, dst_addr)
        udp_header = UDPHeader(self.port, dst_port)
        iter_len = len(message)
        for itr in range(0, iter_len, 2):
            data_len = random.randint(40, 50)
            data_ = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(data_len)). \
                encode()
            udp_header.udp_len = len(data_) + 8
            udp_header.pack_udp_feilds()
            if itr == iter_len - 1:
                ip_header.ip_idf = message[itr]
                ip_header.ip_dfc = 0
            elif itr == iter_len - 2:
                ip_header.ip_idf = struct.unpack('H', message[itr:itr + 2])[0]
                ip_header.ip_dfc = 0
            else:
                ip_header.ip_idf = struct.unpack('H', message[itr:itr + 2])[0]
                ip_header.ip_dfc = 10
            ip_header.pack_ipv4_feilds()
            self.socket.sendto(ip_header.raw + udp_header.raw + data_, (dst_addr, dst_port))
        return

    def send_message_by_packet_len(self, message, dst_addr, dst_port):
        ip_header = IPHeader(self.ip_address, dst_addr)
        udp_header = UDPHeader(self.port, dst_port)
        str_to_bin = ''.join(str(int(format(i, 'b')) + 100000000)[1:] for i in message)
        iter_len = len(str_to_bin)
        for itr in range(iter_len):
            if itr == iter_len - 1:
                ip_header.ip_dfc = 0
            else:
                ip_header.ip_dfc = 10
            if str_to_bin[itr] == '0':
                data_len = random.randint(20, 40)
            else:
                data_len = random.randint(80, 100)
            data_ = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(data_len)). \
                encode()
            udp_header.udp_len = len(data_) + 8
            udp_header.pack_udp_feilds()
            ip_header.ip_idf = random.randint(10000, 65000)
            ip_header.pack_ipv4_feilds()
            self.socket.sendto(ip_header.raw + udp_header.raw + data_, (dst_addr, dst_port))
        return


def host_127_0_0_4():
    host = Host('127.0.0.4', 5544)
    while True:
        print('Host 127.0.0.4\n')
        act = int(input("1 - Send data to 127.0.0.5\n"
                        "2 - Get data from 127.0.0.7\n"))
        if act == 1:
            data = str(input("Input data\n")).encode()
            address, port = host.recv()
            host.send_message_by_ttl_field(data, address, port)
        elif act == 2:
            host.request("127.0.0.7", 5547)
            print(host.recv_message_by_packet_len())
        else:
            break


def host_127_0_0_5():
    host = Host('127.0.0.5', 5545)

    while True:
        print('Host 127.0.0.5\n')
        act = int(input("1 - Send data to 127.0.0.7\n"
                        "2 - Get data from 127.0.0.4\n"
                        "3 - Send data to 127.0.0.6\n"))
        if act == 1 or act == 3:
            data = str(input("Input data\n")).encode()
            address, port = host.recv()
            host.send_message_by_ttl_field(data, address, port)
        elif act == 2:
            host.request("127.0.0.4", 5544)
            print(host.recv_message_by_ttl_field())
        else:
            break


def host_127_0_0_6():
    host = Host('127.0.0.6', 5546)

    while True:
        print('Host 127.0.0.6\n')
        act = int(input("1 - Send data to 127.0.0.7\n"
                        "2 - Get data from 127.0.0.5\n"))
        if act == 1:
            data = str(input("Input data\n")).encode()
            address, port = host.recv()
            host.send_message_by_id_field(data, address, port)
        elif act == 2:
            host.request("127.0.0.5", 5545)
            print(host.recv_message_by_ttl_field())
        else:
            break


def host_127_0_0_7():
    host = Host('127.0.0.7', 5547)

    while True:
        print('Host 127.0.0.7\n')
        act = int(input("1 - Send data to 127.0.0.4\n"
                        "2 - Get data from 127.0.0.5\n"
                        "3 - Get data from 127.0.0.6\n"))
        if act == 1:
            data = str(input("Input data\n")).encode()
            address, port = host.recv()
            host.send_message_by_packet_len(data, address, port)
        elif act == 2:
            host.request("127.0.0.5", 5545)
            print(host.recv_message_by_ttl_field())
        elif act == 3:
            host.request("127.0.0.6", 5546)
            print(host.recv_message_by_id_field())
        else:
            break


def covert_channel_identification(str_, ttl_check=False):

    try:
        sock = subprocess.check_output("ss -ap | grep {}".format(str_), shell=True)
    except subprocess.CalledProcessError:
        print("Socket is not found\n")
        return

    wh_bool = False
    pid = int(sock.decode().split(",")[1].split("=")[1])
    os.system('> sys_log')
    os.system('strace -p {} -s 1024 -xx -q -qq -o sys_log &'.format(pid))
    strace_pid = int(subprocess.check_output("pgrep strace", shell=True).decode())
    kernel_ttl = int(subprocess.check_output(" sysctl net.ipv4.ip_default_ttl", shell=True).decode().split('=')[1])
    while True:
        with open('sys_log') as file:
            for line in file:
                bool_ = False
                if "send" in line:
                    operation = 'send'
                    bool_ = True
                elif "recv" in line:
                    operation = 'recv'
                    bool_ = True
                if bool_:
                    packet = line.split(",")[1]
                    if len(packet) < 20:
                        continue
                    if ttl_check:
                        packet_ttl = int(packet.split('\\x')[9], 16)
                        if packet_ttl != kernel_ttl:
                            print("Warning: covert channel by TTL field; operation - {}\n".format(operation))
                            wh_bool = True
                            os.system("kill {}".format(strace_pid))
                            break
        if wh_bool:
            break
        print("Covert channel is not found\n")
        time.sleep(10)
    return


def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-m', '--mode', help='Program mode. Cases: ident - identification covert channel based '
                                             'TTL attribute;\nhost - run host',
                        required=True, dest='mode', type=str, default=None)
    parser.add_argument('-H', '--host', help='Host in network. Used when mode=host.\n'
                                             'Cases: 127.0.0.4, 127.0.0.5, 127.0.0.6, 127.0.0.7',
                        dest='host', type=str, default=None)
    parser.add_argument('-s', '--socket', help='Analyzable socket.Used when mode=ident.\n'
                                               'Input format: address:port',
                        dest='socket', type=str, default=None)
    return parser.parse_args()


if __name__ == '__main__':
    parser = parse_arguments()
    if parser.mode == 'host':
        if parser.host == '127.0.0.4':
            host_127_0_0_4()
        elif parser.host == '127.0.0.5':
            host_127_0_0_5()
        elif parser.host == '127.0.0.6':
            host_127_0_0_6()
        elif parser.host == '127.0.0.7':
            host_127_0_0_7()
        else:
            print('Enter the correct host value\n')
    elif parser.mode == 'ident':
        covert_channel_identification(parser.socket, ttl_check=True)
    else:
        print('Enter the correct mode value\n')
