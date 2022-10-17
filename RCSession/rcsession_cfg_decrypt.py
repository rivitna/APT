import sys
import io
import struct


CFG_SEED_POS = 0x80


def decrypt(data, seed):
    """RCSession decrypt function"""

    dec_data = b''
    n = seed

    for i, b in enumerate(data):
        m = i & 3
        if (m == 0):
            n += (n >> 4)
        elif (m == 1):
            n -= 2 * n
        elif (m == 2):
            n -= (n >> 2)
        else:
            n *= 9
        n &= 0xFFFFFFFF
        dec_data += bytes([b ^ (n & 0xFF)])

    return dec_data


if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    data = f.read()

seed, = struct.unpack_from("<L", data, CFG_SEED_POS)
dec_data = decrypt(data, seed)

new_filename = filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(dec_data)

print('Done!')
