load_balancer = input("Load Balancer IP Address : ")
host_ip = list(map(str, input("Website Server IP Address (separate by spaces) : ").split()))
listen_port = list(map(int, input("Website Server Port to Monitor (separate by spaces) : ").split()))

f = open("config.py", "w")
f.write("load_balancer = \'")
f.write(load_balancer)
f.write("\'\n")

f.write("host_ip = [")
for i in range(len(host_ip)):
    f.write("\'" + host_ip[i] + "\'")
    if i !=len(host_ip)-1:
        f.write(", ")
f.write("]\n")
f.write("listen_port = [")

for j in range(len(listen_port)):
    f.write(str(listen_port[j]))
    if j!=len(listen_port)-1:
        f.write(", ")
f.write("]")
f.close()