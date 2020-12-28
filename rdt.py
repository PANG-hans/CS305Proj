import traceback
from typing import Tuple

from USocket import UnreliableSocket
import threading
from multiprocessing import Queue
import time
import struct

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
        self.seq = 0
        self.seqack = 0
        self.pkt_que = Queue()
        self.seq_que = Queue()
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


def make_packets(formats: str, bits: int, seq: int, seq_ack: int,
                 data_str: [str, bytes] = "") -> bytes:
    data_bytes: bytes = str_byte_to_str(data_str)
    check_data: int = check_sum(struct.pack(
        formats, bits, seq, seq_ack, len(data_str), 0), data_bytes)
    will_return: bytes = struct.pack(
        formats, bits, seq, seq_ack, len(data_str), check_data) + data_bytes
    assert check_sum(will_return) == 0
    return will_return


class Segment:
    """
    Reliable Data Transfer Segment
    Segment Format:
      0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |VERSION|SYN|FIN|ACK|                  LENGTH                   |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |             SEQ #             |             ACK #             |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                           CHECKSUM                            |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                                                               |
    /                            PAYLOAD                            /
    /                                                               /
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    Protocol Version:           1
    Flags:
     - SYN                      Synchronize
     - FIN                      Finish
     - ACK                      Acknowledge
    Ranges:
     - Payload Length           0 - 1440  (append zeros to the end if length < 1440)
     - Sequence Number          0 - 255
     - Acknowledgement Number   0 - 255
    Checksum Algorithm:         16 bit one's complement of the one's complement sum
    Size of sender's window     16
    """

    HEADER_LEN = 6
    MAX_PAYLOAD_LEN = 1440
    SEGMENT_LEN = MAX_PAYLOAD_LEN + HEADER_LEN
    SEQ_NUM_BOUND = 256

    def __init__(self, payload: bytes, seq_num: int, ack_num: int, syn: bool = False, fin: bool = False,
                 ack: bool = False):
        self.syn = syn
        self.fin = fin
        self.ack = ack
        self.seq_num = seq_num % Segment.SEQ_NUM_BOUND
        self.ack_num = ack_num % Segment.SEQ_NUM_BOUND
        if payload is not None and len(payload) > Segment.MAX_PAYLOAD_LEN:
            raise ValueError
        self.payload = payload

    def encode(self) -> bytes:
        """Returns fixed length bytes"""
        head = 0x4000 | (len(self.payload) if self.payload else 0)  # protocol version: 1
        if self.syn:
            head |= 0x2000
        if self.fin:
            head |= 0x1000
        if self.ack:
            head |= 0x0800
        arr = bytearray(struct.pack('!HBBH', head, self.seq_num, self.ack_num, 0))
        if self.payload:
            arr.extend(self.payload)
        checksum = Segment.calc_checksum(arr)
        arr[4] = checksum >> 8
        arr[5] = checksum & 0xFF
        arr.extend(b'\x00' * (Segment.SEGMENT_LEN - len(arr)))  # so that the total length is fixed
        return bytes(arr)

    @staticmethod
    def parse(segment: Union[bytes, bytearray]) -> 'Segment':
        """Parse raw bytes into an Segment object"""
        try:
            assert len(segment) == Segment.SEGMENT_LEN
            # assert 0 <= len(segment) - 6 <= Segment.MAX_PAYLOAD_LEN
            assert Segment.calc_checksum(segment) == 0
            head, = struct.unpack('!H', segment[0:2])
            version = (head & 0xC000) >> 14
            assert version == 1
            syn = (head & 0x2000) != 0
            fin = (head & 0x1000) != 0
            ack = (head & 0x0800) != 0
            length = head & 0x07FF
            # assert length + 6 == len(segment)
            seq_num, ack_num, checksum = struct.unpack('!BBH', segment[2:6])
            payload = segment[6:6 + length]
            return Segment(payload, seq_num, ack_num, syn, fin, ack)
        except AssertionError as e:
            raise ValueError from e

    @staticmethod
    def calc_checksum(segment: Union[bytes, bytearray]) -> int:
        """
        :param segment: raw bytes of a segment, with its checksum set to 0
        :return: 16-bit unsigned checksum
        """
        i = iter(segment)
        bytes_sum = sum(((a << 8) + b for a, b in zip(i, i)))  # for a, b: (s[0], s[1]), (s[2], s[3]), ...
        if len(segment) % 2 == 1:  # pad zeros to form a 16-bit word for checksum
            bytes_sum += segment[-1] << 8
        # add the overflow at the end (adding twice is sufficient)
        bytes_sum = (bytes_sum & 0xFFFF) + (bytes_sum >> 16)
        bytes_sum = (bytes_sum & 0xFFFF) + (bytes_sum >> 16)
        return ~bytes_sum & 0xFFFF

# header_length = 20
# header_format: str = "!5L"
#
#
# def produce_packets(formats: str, bits: int, seq: int, seq_ack: int,
#                     data_str: [str, bytes] = "") -> bytes:
#     data_bytes: bytes = str_byte_to_str(data_str)
#     check_data: int = check_sum(struct.pack(
#         formats, bits, seq, seq_ack, len(data_str), 0), data_bytes)
#     will_return: bytes = struct.pack(
#         formats, bits, seq, seq_ack, len(data_str), check_data) + data_bytes
#     assert check_sum(will_return) == 0
#     return will_return
#
#
# def str_byte_to_str(data_str: [str, bytes] = "") -> bytes:
#     assert isinstance(data_str, (str, bytes)) is True
#     data_bytes: bytes = b'0'
#     try:
#         if isinstance(data_str, str):
#             data_bytes = bytes(data_str.encode(data_format))
#         elif isinstance(data_str, bytes):
#             data_bytes = data_str
#     except (AttributeError, UnicodeEncodeError) as e:
#         traceback.print_exc()
#     return data_bytes
#
#
# def check_sum(data: bytes, *datas: Tuple[bytes]) -> int:
#     sum: int = 0
#     for byte in data:
#         sum += byte
#     for one_data in datas:
#         for byte in one_data:
#             sum += byte
#     sum = -(sum % (1 << 8))
#     return sum & 0xFF
#
#
# class rdt_header(object):
#     header_length = 20
#
#     def __init__(self, bits: int, seq_num: int, ack_num: int, data_str: [str, bytes] = ""):
#         self.bits: int = bits
#         self.seq_num: int = seq_num
#         self.ack_num: int = ack_num
#         self.length: int = len(data_str)
#
#     @classmethod
#     def unpack(cls, data_bytes: bytes) -> 'rdt_header':
#         if len(data_bytes) < header_length:
#             return cls(0, -1, -1)
#         assert len(data_bytes) >= header_length
#         bits, seq_num, ack_num, length, temp = struct.unpack(header_format, data_bytes[0:header_length])
#         will_return: rdt_header = cls(bits, seq_num, ack_num)
#         will_return.length = length
#         return will_return
#
#     def to_bytes(self) -> bytes:
#         return produce_packets(header_format, self.bits, self.seq_num, self.ack_num, "")
#
#     def equal(self, **args) -> bool:
#         will_return = True
#         if 'bits' in args:
#             will_return = will_return and args['bits'] == self.bits
#         if 'seq_num' in args:
#             will_return = will_return and args['seq_num'] == self.seq_num
#         if 'ack_num' in args:
#             will_return = will_return and args['ack_num'] == self.ack_num
#         if 'length' in args:
#             will_return = will_return and args['length'] == self.length
#         return will_return
#
#     def __str__(self):
#         return "bits:{} seq:{} ack:{} length:{}".format(str(self.bits), str(self.seq_num), str(self.ack_num),
#                                                         str(self.length))
#
