import socket
from threading import Thread

target = input("Enter target IP: ")
ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443]

def scan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((target, port))
        print(f"[+] Port {port} is OPEN")
    except:
        pass
    finally:
        s.close()

for port in ports:
    t = Thread(target=scan, args=(port,))
    t.start()
