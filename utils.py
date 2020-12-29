def int_to_bytes(i: int, b_len: int) -> bytes:
    """
    Convert an non-negative int to big-endian unsigned bytes.
    :param i: The non-negative int.
    :param b_len: The length of bytes converted into.
    :return: The bytes.
    """
    return int.to_bytes(i, length=b_len, byteorder='big', signed=False)


def bytes_to_int(b: bytes) -> int:
    """
    Convert bytes to a big-endian unsigned int.
    :param b: The bytes to be converted.
    :return: The int.
    """
    return int.from_bytes(bytes=b, byteorder='big', signed=False)


def cal_checksum(part: bytes = b'', payload: bytes = b'') -> bytes:
    """
    Calculate the checksum for content of segment.
    :param part: data before checksum
    :param payload: data after checksum
    :return: The checksum. The length of checksum is 2 bytes.
    """

    even_sum = 0x0
    odd_sum = 0x0

    info = part + payload

    for i in range(len(info)):
        b = info[i]
        if i % 2:
            odd_sum += b
            odd_sum %= 256
        else:
            even_sum += b
            even_sum %= 256

    even_sum = int_to_bytes(((256 - even_sum) % 256), 1)
    odd_sum = int_to_bytes(((256 - odd_sum) % 256), 1)
    return odd_sum + even_sum


def judge_checksum(content: bytes) -> bool:
    """
    Judge if the checksum is right or not.
    :param content: the content of segment
    :return: A bool
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

    return even_sum == 0 and odd_sum == 0
