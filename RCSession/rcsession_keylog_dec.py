import sys
import io


def decrypt(data):

    dec_data = b''
    for b in data:
        dec_data += bytes([(((b - 0x61) ^ 0x61) + 0x61) & 0xFF])
    return dec_data


if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

filename = sys.argv[1]

with io.open(filename, 'rb') as f:
    data = f.read()

dec_data = decrypt(data)

new_filename = filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(dec_data)

print('Done!')
