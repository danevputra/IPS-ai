import os
if os.geteuid()!=0:
    print("Please run this program from root user")
    exit()
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
print("starting ...")
import socket
import struct
import textwrap
import keras
from keras.models import load_model
import pickle
from urllib.parse import unquote
import datetime
import re
import time
import csv
import schedule

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

substring = "b'\\x"
substring2 = "Azure TLS"
substring3 = "GET /favicon.ico"
start = "?"
end = " HTTP"
vuln_header = ["User-Agent: ", "X-Api-Version: ", "X-Forwarded-For: "]

global dictionary
dictionary = {}

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    load_balancer = input("Load Balancer/Reverse Proxy IP Address (if you don't have just fill it with server IP): ")
    host_ip = list(map(str, input("Website Server IP Address (separate by spaces) : ").split()))
    listen_port = list(map(int, input("Website Server Port to Monitor (separate by spaces) : ").split()))
    # print(listen_port)
    
    print("ready")
    create_csv()
    schedule.every().hour.do(create_csv)

    while True:
        raw_data,addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        time = str(datetime.datetime.now())
        schedule.run_pending()
        # print('\nEthernet Frame:')
        # print(TAB_1 + 'Destination : {}, Source : {}, Protocol : {}'.format(dest_mac,src_mac,eth_proto))

        #8 for IPv4
        if eth_proto == 8 :
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            #print("data : "+ str(data))
            #print("proto : "+ str(proto))
            temp = 0
            #TCP
            if (target in host_ip) or (target == load_balancer) :
                if proto == 6 :
                    (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
        
                    if (str(data).find(substring)== -1) :

                        # print("\n\ndata : " + str(data.decode('utf-8', 'ignore'))+"\n\n")

                        #syn flood
                        if target == load_balancer and flag_syn == 1 and flag_ack == 0 and (len(str(data.decode('utf-8', 'ignore')))!=0):
                            print_alert(time, dest_mac,src_mac,eth_proto,"DOS",version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,"Syn Flood DOS - if this alert keep popping maybe a DOS attack has launched",data)
                            append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),"DOS","DOS","Syn Flood DOS")
                        
                        #ack flood
                        #udah bisa kl loic, golden eye belom
                        elif target == load_balancer and flag_syn == 0 and flag_ack == 1 and flag_psh == 0 and (len(str(data.decode('utf-8', 'ignore')))!=0):
                            print_alert(time, dest_mac,src_mac,eth_proto,"DOS",version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,"Ack Flood DOS - if this alert keep popping maybe a DOS attack has launched",data)
                            append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),"DOS","DOS","Ack Flood DOS")
                        
                        else :
                            if (dest_port in listen_port) :

                                if (len(data)==0) or (str(data).find(substring2)!= -1) :
                                    temp = 0
                                    # print ("")
                                
                                elif ("\r\n" not in data.decode('utf-8', 'ignore')) :
                                    parsing_data = data.decode('utf-8', 'ignore')
                                    parsing_data = cut_string(parsing_data)
                                    # print("bisa kok" + parsing_data)

                                    status_oneline = predict_sqli_attack(parsing_data)
                                    #print(str(status_oneline))

                                    if float(status_oneline) > 0.5:
                                        print_alert(time, dest_mac,src_mac,eth_proto,status_oneline,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,parsing_data,data)
                                        append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),parsing_data,"1",float(status_oneline))
                                    else :
                                        append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),parsing_data,"0",float(status_oneline))

                                else:
                                    # print(str(data))

                                    #header
                                    # parse_data2 = data.decode('utf-8', 'ignore')
                                    # # print('nih : ' + parse_data2)
                                    # if substring3 not in parse_data2:
                                    #     parse_data2 = parse_data2[:parse_data2.index("\r")]
                                    #     parse_data2 = parse_data2.replace("b\'","")
                                    #     # print("parse_data2 : "+ parse_data2)

                                    #     if parse_data2[:3] == "GET" and parse_data2[5]!= " " and start in parse_data2:
                                    #         # print("parse_data21 : "+ parse_data2)
                                    #         parse_data2 = parse_data2[parse_data2.index(start)+len(start):parse_data2.index(end)]
                                    #         parse_data2 = cut_string(parse_data2)
                                    #         # print("parse_data22 : "+ parse_data2)

                                    #         if (len(parse_data2)!=0):
                                    #             status2 = predict_sqli_attack(parse_data2)
                                    #             #print(str(status))

                                    #             if float(status2) > 0.5:
                                    #                 print_alert(time, dest_mac,src_mac,eth_proto,status2,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,parse_data2,data)
                                    #                 append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),parse_data2,"1",float(status2))
                                    #             else :
                                    #                 append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),parse_data2,"0",float(status2))

                                    #footer
                                    parse_data = data.decode('utf-8', 'ignore').rpartition('\n')[2]
                                    parse_data = cut_string(parse_data)
                                    # print("parse_data : "+ parse_data)

                                    if (len(parse_data)!=0):
                                        status = predict_sqli_attack(parse_data)
                                        #print(str(status))

                                        if float(status) > 0.5:
                                            print_alert(time, dest_mac,src_mac,eth_proto,status,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,parse_data,data)
                                            append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),parse_data,"1",float(status))
                                        else :
                                            append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),parse_data,"0",float(status))
                                    
                                    # #other header
                                    # parse_data3 = data.decode('utf-8', 'ignore')
                                    # # print("parse data 3 : " + parse_data3)
                                    # check_header = []
                                    # check_header.clear()
                                    # check_header = search_vuln_header(parse_data3)
                                    # # print("check header : ")
                                    # # print(check_header)
                                    # for x in range(0, len(check_header)):
                                    #     # print('x : ' + str(x))
                                    #     check_data = re.search(check_header[x]+'(.*)\r\n', parse_data3).group(1)
                                    #     # print("check_data : " +  check_data)
                                    #     if (len(check_data)!=0):
                                    #         status3 = predict_sqli_attack(check_data)
                                    #         #print(str(status))

                                    #         if float(status3) > 0.5:
                                    #             print_alert(time, dest_mac,src_mac,eth_proto,status3,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,check_data,data)
                                    #             append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),check_data,"1",float(status3))
                                    #         else :
                                    #             append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data),check_data,"0",float(status3))

def create_csv():
    global filename
    filename = "log/log_"+str(datetime.datetime.now())+".csv"
    with open(filename, 'w') as f:
        spamwriter = csv.writer(f, doublequote=True, quoting=csv.QUOTE_ALL, lineterminator="\n")
        header = ['Time', 'Source Mac', 'Destination Mac', 'Eth Protocol', 'IPV4 Version', 'Header Length', 'TTL', 'Packet Protocol', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Sequence', 'Acknowledgement', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin', 'all data', 'unique data', 'status' , 'confidence']
        spamwriter.writerow(header)
    f.close()


def append_log(time, src_mac, dest_mac, eth_proto, version, header_length, ttl, protocol, src_ip, dest_ip, src_port, dest_port, sequence, acknowledgement, urg, ack, psh, rst, syn, fin, data, parse_data, status , confidence):
    # print(filename)
    with open(filename,'a') as fd:
        write_outfile = csv.writer(fd)
        write_outfile.writerow([str(time), str(src_mac), str(dest_mac), str(eth_proto), str(version), str(header_length), str(ttl), str(protocol), str(src_ip), str(dest_ip), str(src_port), str(dest_port), str(sequence), str(acknowledgement), str(urg), str(ack), str(psh), str(rst), str(syn), str(fin), str(data), str(parse_data), str(status) , str(confidence)])
    fd.close()


#check header (log4j detection)
def search_vuln_header(data):
    avail_header = []
    avail_header.clear()
    for i in range(len(vuln_header)) :
        if(vuln_header[i]) in data:
            avail_header.append(vuln_header[i])
    return avail_header

def cut_string(parser) :
    parser = parser.replace('=',' ')
    parser = parser.replace('+', ' ')
    parser = parser.replace('&', ' ')
    parser = unquote(parser)
    return parser

#print alert
def print_alert(time, dest_mac,src_mac,eth_proto,status,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,parse_data,data):
    print('=======================================')
    print('ALERT ATTACK HAS OCURRED')
    print('=======================================')
    print('Detection Score : ' + str(status))
    print('=======================================')
    print('Date Time : ' + time)
    print('=======================================')
    print('Time 2 : ' + str(datetime.datetime.now()))
    print('=======================================')
    print('\nEthernet Frame:')
    print(TAB_1 + 'Destination : {}, Source : {}, Protocol : {}'.format(dest_mac,src_mac,eth_proto))
    print('IPv4 Packet:')
    print(TAB_1 + 'Version : {}, Header Length : {}, TTL : {}'.format(version, header_length, ttl))
    print(TAB_1 + 'Protocol : {}, Source : {}, Target : {}'.format(proto, src, target))
    print('TCP Packet:')
    print(TAB_1 + 'Source Port : {}, Destination Port : {}'.format(src_port, dest_port))
    print(TAB_1 + 'Sequence : {}, Acknowledgement : {}'.format(sequence, acknowledgement))
    print(TAB_1 + 'Flags : ')
    print(TAB_2 + 'URG : {}, ACK : {}, PSH : {}, RST : {}, SYN : {}, FIN : {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
    print(TAB_1 + 'Dangerous Payload : ')
    print(DATA_TAB_2 + parse_data)
    print(TAB_1 + 'All Data : \n')
    print(DATA_TAB_2 + str(data.decode('utf-8', 'ignore')).replace('\r\n', '\n\t\t '))
    print('\n============END ATTACK INFO============\n\n')

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
    input_val=input_val.replace('>', ' > ')
    input_val=input_val.replace('/>', ' / > ')
    input_val=input_val.replace('<', ' < ')
    input_val=input_val.replace('|', ' | ')
    input_val=input_val.replace('||', ' | | ')
    input_val=input_val.replace('&', ' & ')
    input_val=input_val.replace('&&', ' & & ')
    input_val=input_val.replace(';', ' ; ')
    input_val=input_val.replace('../', ' . . / ')
    input_val=input_val.replace('\\..', ' \\ . . ')
    input_val=input_val.replace(':/', ' : / ')
    input_val=input_val.replace('/', ' / ')
    input_val=input_val.replace('://', ' : / / ')
    input_val=input_val.replace(':\\', ' : \\ ')
    input_val=input_val.replace('\\', ' \\ ')
    input_val=input_val.replace('\\\\&', ' \\ \\ & ')
    input_val=input_val.replace('{{', ' { { ')
    input_val=input_val.replace('{{[', ' { { [ ')
    input_val=input_val.replace('[', ' [ ')
    input_val=input_val.replace(']', ' ] ')
    input_val=input_val.replace('{', ' { ')
    input_val=input_val.replace('{%', ' { % ')
    input_val=input_val.replace('{$', ' { $ ')
    input_val=input_val.replace('}', ' } ')
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