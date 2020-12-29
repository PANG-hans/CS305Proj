from rdt import *
from threading import *
import time

client_addr = ("127.0.0.1", 8080)
client = RDTSocket()

if __name__ == '__main__':
    client.bind(client_addr)
    client.connect(("127.0.0.1", 9080))
    # while True:
    #     print("sending")
    #     client.sendto(b'1', ("127.0.0.1", 9080))
    #     time.sleep(2)