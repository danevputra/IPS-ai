import socket
import datetime

def create_db() :
    global file_object
    file_object = open('temp.db', 'w')
    file_object.close()

    file_object = open('temp.db', 'a')

def main():
    global minute
    minute = datetime.datetime.now().minute
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    create_db()

    while True:
        raw_data,addr = conn.recvfrom(65536)
        sekarang = datetime.datetime.now().minute

        if sekarang!=minute :
            create_db()
            minute = sekarang
            file_object.write(str(raw_data)+'\n')
        else :
            file_object.write(str(raw_data)+'\n')
    file_object.close()

main()