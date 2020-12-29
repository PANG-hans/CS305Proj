from rdt import *
import time

server_addr = ("127.0.0.1", 8090)
server = RDTSocket()

if __name__ == '__main__':
    server.bind(server_addr)
    conn, addr = server.accept()
