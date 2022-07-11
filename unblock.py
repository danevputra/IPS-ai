import sys
import os

if len(sys.argv)!=2:
    print("Please provide an IP address")
    exit()

ip = sys.argv[1]

data_ip = open('ipdata', 'r')
lines = data_ip.read().splitlines()
data_ip.close()

if ip not in lines :
    print("Invalid IP Address")
    exit()
else :
    os.system("sudo iptables -D INPUT -s "+ ip +" -j DROP")
    os.system('sh -c "iptables-save > /etc/iptables/rules.v4"')
    
    file_object = open('ipdata', 'w')
        
    for i in range(len(lines)):
        if lines[i]!=ip :
            file_object.write(lines[i]+"\n")
        else :
            continue
    
    file_object.close()
    print("IP Unblocked")
    exit()