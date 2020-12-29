import logging
import random
import traceback
from typing import Tuple

import utils_example
from USocket import UnreliableSocket
import threading
import time
import struct
from header import *

from utils import *
from Segment import *



DATA_LENGTH = 2048

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
        self.target = addr
        self.set_send_to(self.sendto)
        self.set_recv_from(self.recvfrom)

        while True:

            # self.setblocking(True)
            recv, addr = self.recvfrom(DATA_LENGTH)
            # self.setblocking(False)
            packet1 = Segment(content=recv)
            self.settimeout(2)
            try:
                if packet1.ack != 1 or \
                        packet1.syn != 1:
                    continue
                while True:
                    try:
                        self.seq = random.randint(0, 1234567)
                        packet2 = Segment(syn=1, seq=self.seq, seq_ack=packet1.getSeq()+1)
                        conn.sendto(packet2.getContent(), addr)
                        recv, addr = self.recvfrom(DATA_LENGTH)
                    #     change to conn.recv(target)
                    except Exception as e:
                        logging.debug(e)
                        print(e)
                        continue
                    if packet3 != recv:
                        continue
                    #     resend p2
                    else:
                        break

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

        self.seq = random.randint(0, 1234567)
        packet1 = Segment(syn=1, seq=self.seq)

        self.settimeout(2)
        self.target = address
        self.set_send_to(self.sendto)
        self.set_recv_from(self.recvfrom)

        self.sendto(packet1.getContent(), address)
        while True:
            try:
                recv, addr = self.recvfrom(DATA_LENGTH)
                packet2 = Segment(content=recv)
                if packet2.getSeqAck() == self.seq+1 \
                        and packet2.ack == 1\
                        and packet2.syn == 1:
                    self.seq = packet2.getSeqAck()
                    packet3 = Segment(seq=self.seq, ack=packet2.getSeq()+1)
                    self.sendto(packet3.getContent(), address)
                    break

            except Exception as e:
                self.sendto(packet1.getContent(), address)
                logging.debug(e)
                print(e)


        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        raise NotImplementedError()
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
        if self.client:
            try:
                self.close_client()
            except ConnectionResetError:
                return
        else:
            self.close_server()
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
        super().close()

    def close_client(self) -> None:
        super().close()

    def close_server(self) -> None:
        super().close()

    def set_send_to(self, send_to):
        self._send_to = send_to

    def set_recv_from(self, recv_from):
        self._recv_from = recv_from


"""
You can define additional functions and classes to do thing such as packing/unpacking packets, or threading.

"""
header_length = 20
header_format: str = "!5L"


def produce_packets(formats: str, bits: int, seq: int, seq_ack: int,
                    data_str: [str, bytes] = "") -> bytes:
    data_bytes: bytes = str_byte_to_str(data_str)
    check_data: int = check_sum(struct.pack(
        formats, bits, seq, seq_ack, len(data_str), 0), data_bytes)
    will_return: bytes = struct.pack(
        formats, bits, seq, seq_ack, len(data_str), check_data) + data_bytes
    assert check_sum(will_return) == 0
    return will_return


def str_byte_to_str(data_str: [str, bytes] = "") -> bytes:
    assert isinstance(data_str, (str, bytes)) is True
    data_bytes: bytes = b'0'
    try:
        if isinstance(data_str, str):
            data_bytes = bytes(data_str.encode(data_format))
        elif isinstance(data_str, bytes):
            data_bytes = data_str
    except (AttributeError, UnicodeEncodeError) as e:
        traceback.print_exc()
    return data_bytes


def check_sum(data: bytes, *datas: Tuple[bytes]) -> int:
    sum: int = 0
    for byte in data:
        sum += byte
    for one_data in datas:
        for byte in one_data:
            sum += byte
    sum = -(sum % (1 << 8))
    return sum & 0xFF


class rdt_header(object):
    header_length = 20

    def __init__(self, bits: int, seq_num: int, ack_num: int, data_str: [str, bytes] = ""):
        self.bits: int = bits
        self.seq_num: int = seq_num
        self.ack_num: int = ack_num
        self.length: int = len(data_str)

    @classmethod
    def unpack(cls, data_bytes: bytes) -> 'rdt_header':
        if len(data_bytes) < header_length:
            return cls(0, -1, -1)
        assert len(data_bytes) >= header_length
        bits, seq_num, ack_num, length, temp = struct.unpack(header_format, data_bytes[0:header_length])
        will_return: rdt_header = cls(bits, seq_num, ack_num)
        will_return.length = length
        return will_return

    def to_bytes(self) -> bytes:
        return produce_packets(header_format, self.bits, self.seq_num, self.ack_num, "")

    def equal(self, **args) -> bool:
        will_return = True
        if 'bits' in args:
            will_return = will_return and args['bits'] == self.bits
        if 'seq_num' in args:
            will_return = will_return and args['seq_num'] == self.seq_num
        if 'ack_num' in args:
            will_return = will_return and args['ack_num'] == self.ack_num
        if 'length' in args:
            will_return = will_return and args['length'] == self.length
        return will_return

    def __str__(self):
        return "bits:{} seq:{} ack:{} length:{}".format(str(self.bits), str(self.seq_num), str(self.ack_num),
                                                        str(self.length))
