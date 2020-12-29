from USocket import UnreliableSocket
import threading
import time
from Segment import *
from utils import *
import random
import logging

DATA_LENGTH = 1024


class RDTSocket(UnreliableSocket):
    """
    The functions with which you are to build your RDT.
    -   recvfrom(bufsize)->bytes, addr
    -   sendto(bytes, address)
    -   bind(address)

    You can set the mode of the socket.
    -   settimeout(timeout)
    -   setblocking(flag)
    By default, a socket is created in the blocking mode.
    https://docs.python.org/3/library/socket.html#socket-timeouts

    """

    def __init__(self, rate=None, debug=True):
        super().__init__(rate=rate)
        self.client = True
        self._rate = rate
        self._send_to = None
        self._recv_from = None
        self.debug = debug
        self.target = ''

        self.seq = 0
        self.seq_ack = 0

        self.established = False
        #############################################################################
        # TODO: ADD YOUR NECESSARY ATTRIBUTES HERE
        #############################################################################

        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################

    def accept(self) -> ('RDTSocket', (str, int)):
        """
        Accept a connection. The socket must be bound to an address and listening for
        connections. The return value is a pair (conn, address) where conn is a new
        socket object usable to send and receive data on the connection, and address
        is the address bound to the socket on the other end of the connection.

        This function should be blocking.
        """
        conn, addr = RDTSocket(self._rate), None
        conn.bind(('127.0.0.1', 10000))
        # self.set_send_to(('127.0.0.1', 10000))
        print("Accept: Create a new Socket.")
        while True:

            # self.setblocking(True)
            print("Accept: Try to receive packet1.")
            recv, addr = self.recvfrom(DATA_LENGTH)
            # self.set_recv_from(addr)
            print("Accept: Receive one packet.")
            # self.setblocking(False)
            packet1 = Segment(content=recv)
            conn.settimeout(3)
            try:
                if packet1.syn != 1:
                    print("Accept: Receive packet1 with error!")
                    time.sleep(0.00001)
                    continue
                # while True:
                try:
                    print("Accept: Receive packet1 correctly.")
                    conn.seq = random.randint(0, 1234567)
                    conn.seq_ack = packet1.getSeq() + 1
                    packet2 = Segment(syn=1, ack=1, seq=conn.seq, seq_ack=conn.seq_ack)
                    conn.sendto(data=packet2.getContent(), addr=addr)
                    print("Accept: Send packet2 for handshaking.")

                    # 第三个包错了不会告诉client， 不会建立链接
                    while True:
                        try:
                            recv, addr = conn.recvfrom(DATA_LENGTH)
                            packet3 = Segment(content=recv)
                            if packet3.ack != 1 or packet3.getSeqAck() != conn.seq + 1:
                                print("Accept: Receive packet3 with error!")
                                time.sleep(0.00001)
                                continue
                            print("Accept: Receive packet3 correctly.")
                            conn.established = True
                            print("Accept: Establish a connection correctly.")
                            return conn, addr
                        except Exception as e:
                            logging.debug(e)
                            print(e)
                            continue

                except Exception as e:
                    logging.debug(e)
                    print(e)
                    continue

            except Exception as e:
                logging.debug(e)
                print(e)
                continue

        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################

        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
        return conn, addr

    def connect(self, address: (str, int)):
        """
        Connect to a remote socket at address.
        Corresponds to the process of establishing a connection on the client side.
        """

        # self.bind(('127.0.0.1', 9100))
        self.seq = random.randint(0, 1234567)
        packet1 = Segment(syn=1, seq=self.seq)
        print("Connect: Create packet1.")

        self.settimeout(1)

        self.sendto(data=packet1.getContent(), addr=address)
        time.sleep(1)
        print("Connect: Send packet1 for handshaking.")
        # return None
        # time.sleep(1)
        while True:
            try:
                time.sleep(1)
                recv, addr = self.recvfrom(DATA_LENGTH)
                self.target = addr
                print("Connect: Receive one packet.")
                packet2 = Segment(content=recv)
                if packet2.getSeqAck() == self.seq + 1 \
                        and packet2.ack == 1 \
                        and packet2.syn == 1:
                    print("Connect: Receive packet2 correctly.")
                    self.seq = packet2.getSeqAck()
                    self.seq_ack = packet2.getSeq() + 1
                    packet3 = Segment(seq=self.seq, seq_ack=self.seq_ack, ack=1)
                    self.sendto(data=packet3.getContent(), addr=self.target)
                    print("Connect: Send packet3 correctly.")
                    self.established = True
                    break
                print("Connect: Receive packet2 with error!")
                time.sleep(1)

            except Exception as e:
                time.sleep(1)
                # self.sendto(data=packet1.getContent(), addr=address)
                logging.debug(e)
                print(e)

        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################

    def recv(self, bufsize: int) -> bytes:
        """
        Receive data from the socket.
        The return value is a bytes object representing the data received.
        The maximum amount of data to be received at once is specified by bufsize.

        Note that ONLY data send by the peer should be accepted.
        In other words, if someone else sends data to you from another address,
        it MUST NOT affect the data returned by this function.
        """
        data = None
        assert self._recv_from, "Connection not established yet. Use recvfrom instead."
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################

        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
        return data

    def send(self, bytes: bytes):
        """
        Send data to the socket.
        The socket must be connected to a remote socket, i.e. self._send_to must not be none.
        """
        assert self._send_to, "Connection not established yet. Use sendto instead."
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        raise NotImplementedError()
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################

    def close(self):
        """
        Finish the connection and release resources. For simplicity, assume that
        after a socket is closed, neither futher sends nor receives are allowed.
        """
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################

        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
        super().close()

    def set_send_to(self, send_to):
        self._send_to = send_to

    def set_recv_from(self, recv_from):
        self._recv_from = recv_from


"""
You can define additional functions and classes to do thing such as packing/unpacking packets, or threading.

"""

