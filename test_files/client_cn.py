from rdt import *
from threading import *
import time

client_addr = ("127.0.0.1", 2000)
client = RDTSocket()

if __name__ == '__main__':
    client.bind(client_addr)
    # client.connect(("127.0.0.1", 9080))
    while True:
        print("sending")
        client.sendto(b'0x123', ("127.0.0.1", 9090))
        time.sleep(2)