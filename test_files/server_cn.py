from rdt import *
import time

server_addr = ("127.0.0.1", 9090)
server = RDTSocket()

if __name__ == '__main__':
    server.bind(server_addr)
    # conn, addr = server.accept()
    # n_server = RDTSocket()
    # n_server.bind(("127.0.0.1", 9080))
    while True:
        print("recving")
        p = server.recvfrom(1024)
        print(p)