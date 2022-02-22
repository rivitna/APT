import sys
import io
import struct
import plugx_xv


if len(sys.argv) != 3:
    print('Usage: '+ sys.argv[0] + ' version filename')
    exit(0)

ver = int(sys.argv[1])
file_name = sys.argv[2]

with io.open(file_name, 'rb') as f:
    data = f.read()

dec_data = b''
i = 0
while (i < len(data)):
    size, = struct.unpack_from('<L', data, i)
    i += 4
    if (size != 0):
        dec_entry = plugx_xv.decrypt_data(ver, data[i : i + size])
        dec_data += dec_entry + b'\x0D\x00\x0A\x00'
        i += size

new_file_name = file_name + '.dec'
with io.open(new_file_name, 'wb') as f:
    f.write(dec_data)

print('Done!')
