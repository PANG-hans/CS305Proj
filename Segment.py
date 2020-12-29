
from utils import *

HEADER_LEN = 14

class Segment:
    """
    [0] Flag(1 Byte): ACK, SYN, FIN, END
    [1:5] SEQ (4 Bytes): Sequence num of the data
    [5:9] SEQACK (4 Bytes): Next sequence num of the data should be
    [9:11] LEN (2 Bytes): The length of data in bytes, at most 2^32-1 bytes
    [12:14] CHECKSUM (2 Bytes): The checksum of the data
    [15:] PAYLOAD
    """

    def __init__(self,
                 syn: int = 0,
                 fin: int = 0,
                 ack: int = 0,
                 end: int = 0,

                 seq: int = 0,
                 seq_ack: int = 0,
                 payload: bytes = b'',
                 content: bytes = None,
                 ):
        """
        initial segment
        :param syn:
        :param fin:
        :param ack:
        :param end:
        :param seq:
        :param seq_ack:
        :param payload: The body of the segment
        :param content: The whole packet of the segment
        """
        # 先判断是否为解包操作
        if content:
            # 解包
            self.flags = content[:1]
            flags_num = bytes_to_int(self.flags)
            binary = bin(flags_num)
            self.syn = binary[-4]
            self.fin = binary[-3]
            self.ack = binary[-2]
            self.end = binary[-1]

            self.seq = content[1:5]
            self.seq_ack = content[5:9]

            self.body_length = content[9:11]
            self.checksum = content[12:14]
            self.payload = content[15:]
            self.content = content


        # 正常的封包进行的操作
        else:
            # 封包
            self.syn = syn
            self.fin = fin
            self.ack = ack
            self.end = end
            flags_num = (syn<<3) + (fin<<2) + (ack<<1) + end
            self.flags = int_to_bytes(flags_num, 1)

            self.seq_ack = int_to_bytes(seq_ack, 4)
            self.seq = int_to_bytes(seq, 4)

            self.payload = payload
            self.body_length = int_to_bytes(len(payload), 2)

            part = self.flags + self.seq + self.seq_ack + self.body_length
            self.checksum = cal_checksum(part)
            self.content = part + self.checksum + self.payload


    def getSeqAck(self) -> int:
        return bytes_to_int(self.seq_ack)

    def getSeq(self) -> int:
        return bytes_to_int(self.seq)

    def getBodyLength(self) -> int:
        return bytes_to_int(self.body_length)

    def getContent(self) -> bytes:
        return self.content

    def check(self) -> bool:
        check_ = False
        if self.checksum == cal_checksum(self.content[:11]):
            check_ = True
        return check_





