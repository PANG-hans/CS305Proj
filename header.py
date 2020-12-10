
class rdt_header(object):

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

