import socket
import struct
import textwrap
import keras
from keras.models import load_model
import pickle

mymodel = load_model('my_model_cnn.h5')
myvectorizer = pickle.load(open("vectorizer_cnn", 'rb'))

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data,addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination : {}, Source : {}, Protocol : {}'.format(dest_mac,src_mac,eth_proto))

        #8 for IPv4
        if eth_proto == 8 :
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            
            #TCP
            if proto == 6 :
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                parse_data = data.decode('utf-8').rpartition('\n')[2]
                if not parse_data:
                    status = predict_sqli_attack(parse_data)

                    if int(status) > 0.5:
                        print(TAB_1 + '========================')
                        print(TAB_1 + 'ALERT ATTACK HAS OCURRED')
                        print(TAB_1 + '========================')
                        print(TAB_1 + 'Detection confidence : ' + str(status))
                        print(TAB_1 + '========================')
                        print(TAB_1 + 'IPv4 Packet:')
                        print(TAB_2 + 'Version : {}, Header Length : {}, TTL : {}'.format(version, header_length, ttl))
                        print(TAB_2 + 'Protocol : {}, Source : {}, Target : {}'.format(proto, src, target))
                        print(TAB_1 + 'TCP Packet:')
                        print(TAB_2 + 'Source Port : {}, Destination Port : {}'.format(src_port, dest_port))
                        print(TAB_2 + 'Sequence : {}, Acknowledgement : {}'.format(sequence, acknowledgement))
                        print(TAB_2 + 'Flags : ')
                        print(TAB_3 + 'URG : {}, ACK : {}, PSH : {}, RST : {}, SYN : {}, FIN : {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                        print(TAB_2 + 'Data : ')
                        print(DATA_TAB_3 + data)

#unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#return properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#Return properly formatted IPV4 address
def ipv4(addr):
    return '.'.join(map(str,addr))

# Unpacks TCP packet
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


def clean_data(input_val):

    input_val=input_val.replace('\n', '')
    input_val=input_val.replace('%20', ' ')
    input_val=input_val.replace('=', ' = ')
    input_val=input_val.replace('((', ' (( ')
    input_val=input_val.replace('))', ' )) ')
    input_val=input_val.replace('(', ' ( ')
    input_val=input_val.replace(')', ' ) ')
    input_val=input_val.replace('1 ', 'numeric')
    input_val=input_val.replace(' 1', 'numeric')
    input_val=input_val.replace("'1 ", "'numeric ")
    input_val=input_val.replace(" 1'", " numeric'")
    input_val=input_val.replace('1,', 'numeric,')
    input_val=input_val.replace(" 2 ", " numeric ")
    input_val=input_val.replace(' 3 ', ' numeric ')
    input_val=input_val.replace(' 3--', ' numeric--')
    input_val=input_val.replace(" 4 ", ' numeric ')
    input_val=input_val.replace(" 5 ", ' numeric ')
    input_val=input_val.replace(' 6 ', ' numeric ')
    input_val=input_val.replace(" 7 ", ' numeric ')
    input_val=input_val.replace(" 8 ", ' numeric ')
    input_val=input_val.replace('1234', ' numeric ')
    input_val=input_val.replace("22", ' numeric ')
    input_val=input_val.replace(" 8 ", ' numeric ')
    input_val=input_val.replace(" 200 ", ' numeric ')
    input_val=input_val.replace("23 ", ' numeric ')
    input_val=input_val.replace('"1', '"numeric')
    input_val=input_val.replace('1"', '"numeric')
    input_val=input_val.replace("7659", 'numeric')
    input_val=input_val.replace(" 37 ", ' numeric ')
    input_val=input_val.replace(" 45 ", ' numeric ')

    return input_val

def predict_sqli_attack(data):

    input_val=data
    input_val=clean_data(input_val)
    input_val=[input_val]
    input_val=myvectorizer.transform(input_val).toarray()
    input_val.shape=(1,64,64,1)
    result=mymodel.predict(input_val)

    return result

main()