import os
if os.geteuid()!=0:
    print("Please run this program from root user")
    exit()
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
print("starting ...")
import socket
import struct
import keras
from keras.models import load_model
import pickle
from urllib.parse import unquote
import datetime
import re
import csv
import schedule
import numpy as np
import config

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
vuln_header = ["User-Agent: ", "X-Api-Version: ", "X-Forwarded-For: ", "Client-IP: "]

def main():

    if (len(config.load_balancer)<1 or len(config.host_ip)<1 or len(config.listen_port)<1):
        print("Please do a proper configuration\n")
        exit()
    load_balancer = config.load_balancer
    host_ip = config.host_ip
    listen_port = config.listen_port
    global iterate
    iterate = 0
    global ori_ip
    ori_ip = load_balancer
    
    print("ready")
    create_csv()
    schedule.every().hour.do(create_csv)

    while True:
        f = open("temp.db", "r")
        lines = f.readlines()
        # print(len(lines))
        # sekarang = datetime.datetime.now().minute
        # print(iterate)
        if len(lines)+1 < iterate :
            iterate = 0
            # minute = sekarang

        if len(lines) < 1 or iterate>=len(lines):
            iterate = iterate
            f.close()
            continue
        elif "tmicrosoft" in lines[iterate] :
            iterate +=1
            f.close()
            continue
        elif lines[iterate][0:2]!="b\'" or lines[iterate][0:2]!="b\"" :
            raw_data = eval(lines[iterate])
            f.close()
            iterate+=1
            # print(raw_data)
            # print("\n\n")

            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            time = str(datetime.datetime.now())
            schedule.run_pending()
            # print('\nEthernet Frame:')
            # print(TAB_1 + 'Destination : {}, Source : {}, Protocol : {}'.format(dest_mac,src_mac,eth_proto))

            #8 for IPv4
            if eth_proto == 8 :
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                temp = 0
                # print("source : " + str(src) + "\n")

                #TCP
                if ((target in host_ip) or (target == load_balancer)) and (proto == 6) :
                    (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data_original) = tcp_segment(data)

                    # print("sequence : " + str(sequence) + "\n")
        
                    if (str(data_original).find(substring)== -1) :

                        data = str(data_original.decode('utf-8', 'ignore'))

                        cut_ori = "X-Forwarded-For: "
                        if (load_balancer!=host_ip) and (cut_ori in data) :
                            ori_ip = re.search(cut_ori+'(.*)\r\n', data).group(1)     
                        #print(ori_ip)
                        # print("data : "+data)
                        #syn flood
                        if target == load_balancer and flag_syn == 1 and flag_ack == 0 and (len(data)!=0):
                            time_syn = str(datetime.datetime.now())
                            print_alert(time, time_syn, src, dest_mac,src_mac,eth_proto,"DOS",version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,"Syn Flood DOS - if this alert keep popping maybe a DOS attack has launched",data)
                            append_log(time, time_syn, src, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),"DOS","DOS","Syn Flood DOS")
                            block_ip(src)
                        
                        #ack flood
                        #udah bisa kl loic, golden eye belom
                        elif target == load_balancer and flag_syn == 0 and flag_ack == 1 and flag_psh == 0 and (len(data)!=0):
                            time_ack = str(datetime.datetime.now())
                            print_alert(time, time_ack, src, dest_mac,src_mac,eth_proto,"DOS",version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,"Ack Flood DOS - if this alert keep popping maybe a DOS attack has launched",data)
                            append_log(time, time_ack, src, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),"DOS","DOS","Ack Flood DOS")
                            block_ip(src)
                        
                        else :
                            if (dest_port in listen_port) :

                                if (len(data_original)==0) or (str(data_original).find(substring2)!= -1) :
                                    temp = 0
                                
                                elif ("\r\n" not in data) :
                                    raw_data = data

                                    arr1 = cut_input(raw_data)

                                    for i in range(len(arr1)):
                                        parsing_data = cut_string(arr1[i])
                                        parsing_data = parsing_data.split("=", 1)[1]
                                        # print("bisa kok" + parsing_data)

                                        status_oneline = predict_sqli_attack(parsing_data)
                                        #print("status_oneline" + str(type(status_oneline)))
                                        #print(str(status_oneline))
                                        time2_1 = str(datetime.datetime.now())

                                        if float(status_oneline) > 0.5:
                                            print_alert(time, time2_1, ori_ip, dest_mac,src_mac,eth_proto,status_oneline,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,parsing_data,data)
                                            append_log(time, time2_1, ori_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),parsing_data,"1",float(status_oneline))
                                            block_ip(ori_ip)
                                        else :
                                            append_log(time, time2_1, ori_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),parsing_data,"0",float(status_oneline))

                                else:
                                    # print(str(data))

                                    #header
                                    parse_data2 = data
                                    # print('nih : ' + parse_data2)
                                    if substring3 not in parse_data2:
                                        parse_data2 = parse_data2[:parse_data2.index("\r")]
                                        # parse_data2 = parse_data2.replace("b\'","")
                                        parse_data2 = re.sub(r"b\'","",parse_data2)    
                                        # print("parse_data2 : "+ parse_data2)

                                        if parse_data2[:3] == "GET" and parse_data2[5]!= " " and start in parse_data2:
                                            parse_data2 = parse_data2[parse_data2.index(start)+len(start):parse_data2.index(end)]
                                            arr2 = cut_input(parse_data2)

                                            for j in range(len(arr2)):
                                                parse_data2 = cut_string(arr2[j])
                                                if (len(parse_data2)!=0):
                                                    parse_data2 = parse_data2.split("=", 1)[1]
                                                    status2 = predict_sqli_attack(parse_data2)
                                                    #print("status2" + str(type(status2)))
                                                    #print(str(status2))
                                                    time2_2 = str(datetime.datetime.now())

                                                    if float(status2) > 0.5:
                                                        print_alert(time, time2_2, ori_ip, dest_mac,src_mac,eth_proto,status2,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,parse_data2,data)
                                                        append_log(time, time2_2, ori_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),parse_data2,"1",float(status2))
                                                        block_ip(ori_ip)
                                                    else :
                                                        append_log(time, time2_2, ori_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),parse_data2,"0",float(status2))

                                    #footer
                                    parse_data = data.rpartition('\n')[2]
                                    arr3 = cut_input(parse_data)

                                    for k in range(len(arr3)):
                                        parse_data = cut_string(arr3[k])
                                        # print("parse_data : "+ parse_data)

                                        if (len(parse_data)!=0):
                                            parse_data = parse_data.split("=", 1)[1]
                                            status = predict_sqli_attack(parse_data)
                                            #print("status" + str(type(status)))
                                            #print(str(status))
                                            time2_3 = str(datetime.datetime.now())

                                            if float(status) > 0.5:
                                                print_alert(time, time2_3, ori_ip, dest_mac,src_mac,eth_proto,status,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,parse_data,data)
                                                append_log(time, time2_3, ori_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),parse_data,"1",status)
                                                block_ip(ori_ip)
                                            else :
                                                append_log(time, time2_3, ori_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),parse_data,"0",status)
                                    
                                    #other header
                                    parse_data3 = data
                                    check_header = []
                                    check_header.clear()
                                    check_header = search_vuln_header(parse_data3)
                                    # print("check header : ")
                                    # print(check_header)
                                    for x in range(0, len(check_header)):
                                        # print('x : ' + str(x))
                                        check_data = re.search(check_header[x]+'(.*)\r\n', parse_data3).group(1)
                                        # print("check_data : " +  check_data)
                                        if (len(check_data)!=0):
                                            status3 = predict_sqli_attack(check_data)
                                            #print("status 3 " + str(type(status3)))
                                            #print(status3)
                                            #print(str(status))
                                            time2_4 = str(datetime.datetime.now())

                                            if float(status3) > 0.5:
                                                print_alert(time, time2_4, ori_ip, dest_mac,src_mac,eth_proto,status3,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,check_data,data)
                                                append_log(time, time2_4, ori_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),check_data,"1",float(status3))
                                                block_ip(ori_ip)
                                            else :
                                                append_log(time, time2_4, ori_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,str(data_original),check_data,"0",float(status3))

def create_csv():
    global filename
    filename = "log/log_"+str(datetime.datetime.now())+".csv"
    with open(filename, 'w') as f:
        spamwriter = csv.writer(f, doublequote=True, quoting=csv.QUOTE_ALL, lineterminator="\n")
        header = ['Time', 'Detection Finished', 'Source Mac', 'Destination Mac', 'Eth Protocol', 'IPV4 Version', 'Header Length', 'TTL', 'Packet Protocol', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Sequence', 'Acknowledgment', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin', 'all data', 'real user ip', 'unique data', 'status' , 'Detection Score']
        spamwriter.writerow(header)
    f.close()


def append_log(time, time2, real_ip, src_mac, dest_mac, eth_proto, version, header_length, ttl, protocol, src_ip, dest_ip, src_port, dest_port, sequence, acknowledgement, urg, ack, psh, rst, syn, fin, data, parse_data, status , confidence):
    # print(filename)
    with open(filename,'a') as fd:
        write_outfile = csv.writer(fd, lineterminator="\n")
        write_outfile.writerow([str(time), str(time2), str(src_mac), str(dest_mac), str(eth_proto), str(version), str(header_length), str(ttl), str(protocol), str(src_ip), str(dest_ip), str(src_port), str(dest_port), str(sequence), str(acknowledgement), str(urg), str(ack), str(psh), str(rst), str(syn), str(fin), str(data), str(real_ip), str(parse_data), str(status) , str(confidence)])
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
    # parser = re.sub(r'=',' ',parser)
    parser = re.sub(r'\+',' ',parser)
    # parser = re.sub(r'&',' ',parser)
    parser = unquote(parser)
    return parser

def cut_input(string):
    arr = []
    while "&" in string:
        temp = string.split("&", 1)[0]
        if string.split("&", 1)[1] :
            string = string.split("&", 1)[1]
        arr.append(temp)
    arr.append(string)
    return arr

#print alert
def print_alert(time, time2, real_ip, dest_mac,src_mac,eth_proto,status,version,header_length,ttl,proto,src,target,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,parse_data,data):
    print('=======================================')
    print('ALERT ATTACK HAS OCURRED')
    print('=======================================')
    print('Detection Score : ' + str(status))
    print('=======================================')
    print('Date Time : ' + time)
    print('=======================================')
    print('Detection Finished at : ' + time2)
    print('=======================================')
    print('\nEthernet Frame:')
    print(TAB_1 + 'Destination : {}, Source : {}, Protocol : {}'.format(dest_mac,src_mac,eth_proto))
    print('IPv4 Packet:')
    print(TAB_1 + 'Version : {}, Header Length : {}, TTL : {}'.format(version, header_length, ttl))
    print(TAB_1 + 'Protocol : {}, Source : {}, Target : {}'.format(proto, src, target))
    print('TCP Packet:')
    print(TAB_1 + 'Source Port : {}, Destination Port : {}'.format(src_port, dest_port))
    print(TAB_1 + 'Sequence : {}, Acknowledgment : {}'.format(sequence, acknowledgement))
    print(TAB_1 + 'Flags : ')
    print(TAB_2 + 'URG : {}, ACK : {}, PSH : {}, RST : {}, SYN : {}, FIN : {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
    print(TAB_1 + 'Dangerous Payload : ')
    print(DATA_TAB_2 + parse_data)
    print(TAB_1 + 'Real IP : ')
    print(DATA_TAB_2 + real_ip)
    print(TAB_1 + 'All Data : \n')
    print(DATA_TAB_2 + re.sub(r'\r\n', '\n\t\t ',data))
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
    input_val=input_val.replace('.', ' . ')
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
    if input_val=="submit" or input_val=="Submit" :
        return 0
    input_val=clean_data(input_val)
    input_val=[input_val]
    input_val=myvectorizer.transform(input_val).toarray()
    input_val.shape=(1,64,64,1)
    result=mymodel.predict(input_val)
    return str(result[0][0])

def block_ip(ip_address):
    data_ip = open('ipdata', 'r')
    lines = data_ip.read().splitlines()
    data_ip.close()

    if ip_address not in lines:
        file_object = open('ipdata', 'a')
        file_object.write(ip_address + "\n")
        file_object.close()
        os.system("iptables -A INPUT -s "+ ip_address +" -j DROP")
        os.system('sh -c "iptables-save > /etc/iptables/rules.v4"')

main()