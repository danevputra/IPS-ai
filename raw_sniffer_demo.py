import socket
import config
import struct
import os

def create_db() :
    global file_object
    file_object = open('temp.db', 'w')
    file_object.close()

def append_db(raw_data):
    file_object = open('temp.db', 'a')
    file_object.write(str(raw_data)+'\n')
    file_object.close()

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    create_db()

    while True:
        raw_data,addr = conn.recvfrom(65536)
        
        statinfo = os.stat('temp.db')
        if statinfo.st_size >= 10485760:
            create_db()
        
        append_db(raw_data)

main()
