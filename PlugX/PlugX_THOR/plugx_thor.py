import struct


def decrypt1(data):

    dec_data = b''

    n1, = struct.unpack_from('<L', data, 0)
    n2 = n1
    n3 = n1
    n4 = n1

    for i in range(len(data)):
        n1 = (n1 + (n1 >> 3) - 0x56565656) & 0xFFFFFFFF
        n2 = (n2 + (n2 >> 5) - 0x36363636) & 0xFFFFFFFF
        n3 = (n3 - (n3 << 7) + 0x57575757) & 0xFFFFFFFF
        n4 = (n4 - (n4 << 9) - 0x76767677) & 0xFFFFFFFF
        b = (data[i] ^ (n1 + n2 + n3 + n4)) & 0xFF
        dec_data += bytes([b])

    return dec_data


def decrypt2(data, start_pos=16):

    dec_data = b''

    n1, = struct.unpack_from('<L', data, 0)
    n2 = n1
    n3 = n1
    n4 = n1

    for i in range(start_pos, len(data)):
        n1 = (n1 + (n1 >> 3) - 0x66666666) & 0xFFFFFFFF
        n2 = (n2 + (n2 >> 5) + 0x76767677) & 0xFFFFFFFF
        n3 = (n3 - (n3 << 7) + 0x67676767) & 0xFFFFFFFF
        n4 = (n4 - (n4 << 9) - 0x66666667) & 0xFFFFFFFF
        b = (data[i] ^ (n1 + n2 + n3 + n4)) & 0xFF
        dec_data += bytes([b])

    return dec_data


if __name__ == '__main__':
    import sys
    import io

    if len(sys.argv) != 2:
        print('Usage: '+ sys.argv[0] + ' filename')
        sys.exit(0)

    file_name = sys.argv[1]
    with io.open(file_name, 'rb') as f:
        data = f.read()

    dec_data = decrypt(data)

    new_file_name = file_name + '.dec'
    with io.open(new_file_name, 'wb') as f:
        f.write(dec_data)

    print('Done!')
