

def int_to_bytes(i: int, b_len: int) -> bytes:
    """
    Convert an non-negative int to big-endian unsigned bytes.
    :param i: The non-negative int.
    :param b_len: The length of bytes converted into.
    :return: The bytes.
    """
    return i.to_bytes(length=b_len, byteorder='big', signed=False)


def bytes_to_int(b: bytes) -> int:
    """
    Convert bytes to a big-endian unsigned int.
    :param b: The bytes to be converted.
    :return: The int.
    """
    return int.from_bytes(bytes=b, byteorder='big', signed=False)

def cal_checksum(content: bytes) -> bytes:
    """
    Calculate the checksum for content of segment.
    :param packet: The packet to generate checksum.
    :return: The checksum. The length of checksum is 2 bytes.
    """

    even_sum = 0x0
    odd_sum = 0x0

    for i in range(len(content)):
        b = content[i]
        if i % 2:
            odd_sum += b
            odd_sum %= 256
        else:
            even_sum += b
            even_sum %= 256

    even_check = int_to_bytes(((256 - even_sum) % 256), 1)
    odd_check = int_to_bytes(((256 - odd_sum) % 256), 1)
    return odd_check + even_check

