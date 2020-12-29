import traceback
from enum import Enum
from typing import Tuple

from USocket import UnreliableSocket
from threading import *
from multiprocessing import Queue
import time
import struct
import queue
from Segment import *

udp_pkt_len: int = 500  # 单个udp包的长度

udp_pkt_len: int = 500  # 单个udp包的长度
class Status(Enum):
    Closed = 0
    Active = 1
    Active_fin1 = 2
    Active_fin2 = 3
    Passive_fin1 = 4
    Passive_fin2 = 5

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
        self.seq = 0
        self.seqack = 0
        self.pkt_que = Queue()
        self.seq_que = Queue()
        self.status = Status.Closed
        self.process_thread = Thread(target=self.process_threading)
        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################

    def accept(self) -> ("RDTSocket", (str, int)):
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

    def receving(self):
        while 1:
            recv, addr = self.recvfrom(2048)
            recv = Segment.parse(recv)
            if len(recv.payload) == 0 and not recv.fin:
                self.ack_list.append(recv)
            else:
                self.content_list.append(recv)

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

    def send(self, content_bytes: bytes) -> bool:
        """
        Send data to the socket. 
        The socket must be connected to a remote socket, i.e. self._send_to must not be none.
        """
        assert self._send_to, "Connection not established yet. Use sendto instead."
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
        # 当前信息的局部seq
        idx = 0
        # 打包前n-1个包
        for _ in range(pkt_num - 1):
            content = content_bytes[idx: idx + udp_pkt_len]
            # 非最后一个包
            self.pkt_que.put(Segment(seq=self.seq+idx, seq_ack=self.seqack))
            self.seq_que.put(self.seq + idx)
            idx += len(content)
        # 最后一个包单独拼接
        seq_list.append(idx)
        packet_list.append(make_packets(header_format, pkt_num, idx, cur_seqack, cur_content))

        max_ack = -1
        base = 0
        # 开一个线程用于接收数据？
        threading.Thread(target=self.receing).start()

        while base != pkt_num:
            send_seg = Segment(payload=packet_list[base], ack=True, ack_num=self.ack, seq_num=base)
            self.sendto(send_seg.encode(), self._connect_addr)
            print('send_seq: ' + str(base))
            temp = base
            while temp == base:
                if self.ack_list:
                    receive_seq = self.ack_list[0].ack_num
                    print('recv_ack: ' + str(receive_seq))
                    self.ack_list.pop(0)
                    if receive_seq < base:
                        send_seg = Segment(payload=window[base - 1], ack=True, ack_num=self.ack_num, seq_num=base)
                        self.sendto(send_seg.encode(), self._connect_addr)
                        print('resend_seq: ' + str(base - 1))
                    else:
                        base += 1
                else:
                    send_seg = Segment(payload=window[base], ack=True, ack_num=self.ack_num, seq_num=base)
                    self.sendto(send_seg.encode(), self._connect_addr)
                    print('resend_seq: ' + str(base))
                time.sleep(0.01)

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

        while self.status != Status.Closed:
            if self.status == Status.Active:
                self.status = Status.Active_fin1
            elif self.status == Status.Passive_fin1:
                self.status = Status.Passive_fin2
            while not True:
                time.sleep(1)
            #check and process send queue
            finpkt = Segment()
            if self.pkt_que.empty():
                finpkt = Segment(fin=1, seq=self.seq + 1, seq_ack=self.seqack)
            else:
                temp = Segment(self.pkt_que.get())
                finpkt = Segment(fin=1, seq=temp.getSeq() + 1, seq_ack=temp.getSeqAck()+1)

            if finpkt.fin == 1:
                self._send(finpkt)

        #############################################################################
        #                             END OF YOUR CODE                              #
        #############################################################################
    def _close(self):
        print("Closed socket to: ", self._send_to)
        while not self.empty():
            time.sleep(1)
        self.status = Status.Closed

        super().close()

    def process_threading(self):
        while True:
            while self.status != Status.Closed and self.recv_queue.empty():
                time.sleep(0.0001)
            if self.status == Status.Closed:
                break
            msg = self.recv_queue.get()
            recv_dataHead = Segment(msg)
            if self.client:
                if recv_dataHead.fin == 1:
                    if recv_dataHead.ack == 1:
                        if self.status == Status.Active_fin1:
                            self.status = Status.Active_fin2
                        elif self.status == Status.Passive_fin2:
                            self.status = Status.Closed
                            self._close()
                    else:
                        self.recv_data_buffer.append(b'')
                        self._send(Segment(fin=1, ack=1))
                        if self.status in (Status.Active_fin1, Status.Active_fin2):
                            self._close()
                        elif self.status == Status.Active:
                            self.status = Status.Passive_fin1

    def _send(self, Segment):
        self.seq_que.put(Segment)


    def set_send_to(self, send_to):
        self._send_to = send_to

    def set_recv_from(self, recv_from):
        self._recv_from = recv_from


"""
You can define additional functions and classes to do thing such as packing/unpacking packets, or threading.

"""
