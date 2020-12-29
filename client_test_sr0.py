from rdt import *
from threading import *
import time

client_addr = ("127.0.0.1", 8080)
client = RDTSocket()

if __name__ == '__main__':
    client.bind(client_addr)
    client.connect(("127.0.0.1", 8090))

    # start = time.time()
    # with open("/test_files/alice.txt", 'rb') as file:
    #     data = file.read()
    # client.send(data)
    #
    # with open("../dst/补充说明4.pdf", mode='wb') as file:
    #     data = client.recv(1024000000)
    #     print("-----------------------")
    #     print("Server Receive!", time.time() - start)
    #     print("-----------------------")
    #     file.write(data)
    #
    # client.close()