import traceback
from typing import Tuple

from USocket import UnreliableSocket
import threading
import time
import struct
import queue
from Segment import *

udp_pkt_len: int = 500  # 单个udp包的长度


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
        #############################################################################
        # TODO: ADD YOUR NECESSARY ATTRIBUTES HERE
        #############################################################################
        self.seq = 0  # 指当前的序号
        self.seqack = 0  # 指需要对方的包的序号
        self.pkt_que = queue.Queue()  # 等待发出的包的队列
        self.ack_que = queue.Queue()  # 接收到的包的队列
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################

    def accept(self) -> (RDTSocket, (str, int)):
        """
        Accept a connection. The socket must be bound to an address and listening for
        connections. The return value is a pair (conn, address) where conn is a new
        socket object usable to send and receive data on the connection, and address
        is the address bound to the socket on the other end of the connection.

        This function should be blocking.
        """
        conn, addr = RDTSocket(self._rate), None
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

    def send(self, content_bytes: bytes = None) -> bool:
        """
        Send data to the socket.
        The socket must be connected to a remote socket, i.e. self._send_to must not be none.
        """
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        # 检测连接是否正常
        if self._send_to is None:
            print("No Connection")
            return False
        # 检测发送内容是否正常
        if content_bytes is None:
            print("No Data")
            return False
        # 消息总长度
        length = len(content_bytes)
        # 一共切分包的个数
        pkt_num = length // udp_pkt_len + 1 if length % udp_pkt_len != 0 else length // udp_pkt_len
        idx = 0
        # 将每个包单独打包
        for i in range(pkt_num):
            content = content_bytes[idx: idx + udp_pkt_len]
            self.pkt_que.put(
                Segment(end=0 if i < pkt_num - 1 else 1, seq=self.seq, seq_ack=self.seqack, payload=content))
            self.seq += len(content)
            idx += udp_pkt_len

        return True
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
