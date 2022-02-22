import struct


def decrypt(data):
    dec_data = b''
    data_len = len(data)
    n1, = struct.unpack_from('<L', data, 0)
    n2 = n1
    n3 = n1
    n4 = n1
    for i in range(data_len):
        n1 = (n1 + (n1 >> 3) - 0x11111111) & 0xFFFFFFFF
        n2 = (n2 + (n2 >> 5) - 0x22222222) & 0xFFFFFFFF
        n3 = (n3 + (0x33333333 - (n3 << 7))) & 0xFFFFFFFF
        n4 = (n4 + (0x44444444 - (n4 << 9))) & 0xFFFFFFFF
        b = (data[i] ^ (n2 + n1 + n3 + n4)) & 0xFF
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
