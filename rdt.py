import traceback
from typing import Tuple

from USocket import UnreliableSocket
import threading
import time
import struct
from multiprocessing import Queue
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
        self.established = False
        #############################################################################
        # TODO: ADD YOUR NECESSARY ATTRIBUTES HERE
        #############################################################################
        self.seq = 0  # 指当前的序号
        self.seq_ack = 0  # 指需要对方的包的序号
        self.pkt_que = Queue()  # 等待发出的包的队列
        self.recv_que = Queue()  # 接收到的包的队列
        self.recv_msg = [b'']  # 收到的消息的buffer

        self.timers = Queue()  # 已发出还未确认结果的计时器

        self.win_size = 5  # 窗口大小
        self.win_idx = 0  # 窗口首位

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

    # 主进程用于控制收发包以及连接关闭
    def main_threading(self):
        while True:
            # 如果没有建立连接或者连接关闭了，就不要浪费资源了
            if not self.established:
                break
            # 如果队列是空的，那就等等吧，没啥包需要等待的
            if self.recv_que.empty():
                time.sleep(0.00001)
                continue
            first_pkt = self.recv_que.get()

    # 收包线程，持续检测是否有包需要接收
    def recv_threading(self):
        while True:
            # 如果连接都没有建立或者连接关闭了，就不要浪费资源了
            if not self.established:
                break
            recv_content, addr = self.recvfrom(8192)
            self.recv_que.put(Segment(recv_content))
            time.sleep(0.00001)

    def recv(self, bufsize: int) -> bytes:
        """
        Receive data from the socket.
        The return value is a bytes object representing the data received.
        The maximum amount of data to be received at once is specified by bufsize.

        Note that ONLY data send by the peer should be accepted.
        In other words, if someone else sends data to you from another address,
        it MUST NOT affect the data returned by this function.
        """
        assert self._recv_from, "Connection not established yet. Use recvfrom instead."
        #############################################################################
        # TODO: YOUR CODE HERE                                                      #
        #############################################################################
        # 消息没收完并且长度还不够bufsize的大小，继续等待
        while len(self.recv_msg) <= 1 and len(self.recv_msg[0]) < bufsize:
            time.sleep(0.00001)

        cur_msg = self.recv_msg[0]
        # 将已返回的消息从buf中删去
        self.recv_msg[0] = cur_msg[bufsize:]
        # 如果收到的这条消息已经被返回干净了，那就删除这个消息占用的buf
        if len(self.recv_msg[0]) == 0:
            self.recv_msg = self.recv_msg[1:]
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
        return cur_msg[:bufsize]

    # 发包线程，持续检测是否有包需要发送
    def send_threading(self):
        while True:
            # 如果连接都没有建立或者连接关闭了，就不要浪费资源了
            if not self.established:
                break
            if not self.pkt_que.empty():
                pkt = self.pkt_que.get()
                self.sendto(pkt.getContent(), self._send_to)
            time.sleep(0.00001)

    def send(self, payload_bytes: bytes = None) -> bool:
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
        if payload_bytes is None:
            print("No Data")
            return False
        # 消息总长度
        length = len(payload_bytes)
        # 一共切分包的个数
        pkt_num = length // udp_pkt_len + 1 if length % udp_pkt_len != 0 else length // udp_pkt_len
        idx = 0
        # 将每个包单独打包
        for i in range(pkt_num):
            payload = payload_bytes[idx: idx + udp_pkt_len]
            # 将包打包并放入队列中等待发出
            self.pkt_que.put(
                Segment(end=0 if i < pkt_num - 1 else 1, seq=self.seq, seq_ack=self.seq_ack, payload=payload))
            self.seq += len(payload)
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
