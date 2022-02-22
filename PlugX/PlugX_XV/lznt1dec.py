import struct


def decompress(data):
    """LZNT1 decompression"""

    dec_data = bytearray()
    data_len = len(data)
    written = 0
    i = 0
    while (i < data_len):
        chunk_hdr, = struct.unpack_from('<H', data, i)
        if (((chunk_hdr >> 8) & 0x70) != 0x30):
            break
        chunk_len = (chunk_hdr & 0x0FFF) + 1
        i += 2
        if (((chunk_hdr >> 8) & 0x80) != 0):
            chunk_written = 0
            next_threshold = 16
            split = 12
            tag_bit = 0
            j = 0
            while (j < chunk_len):
                if (tag_bit == 0):
                    tag = data[i + j]
                    j += 1
                if ((tag & 1) != 0):
                    while (chunk_written > next_threshold):
                        split -= 1
                        next_threshold <<= 1
                    n, = struct.unpack_from('<H', data, i + j)
                    j += 2
                    copy_len = (n & ((1 << split) - 1)) + 3
                    copy_from = written - ((n >> split) + 1)
                    for k in range(copy_len):
                        dec_data.append(dec_data[copy_from + k])
                        chunk_written += 1
                        written += 1
                else:
                    dec_data.append(data[i + j])
                    j += 1
                    chunk_written += 1
                    written += 1
                tag >>= 1
                tag_bit = (tag_bit + 1) & 7
        else:
            for j in range(chunk_len):
                dec_data.append(data[i + j])
                written += 1
        i += chunk_len
    return bytes(dec_data)


if __name__ == '__main__':
    import sys
    import io

    if len(sys.argv) != 2:
        print('Usage: '+ sys.argv[0] + ' filename')
        sys.exit(0)

    file_name = sys.argv[1]
    with io.open(file_name, 'rb') as f:
        data = f.read()

    dec_data = decompress(data)

    new_file_name = file_name + '.dec'
    with io.open(new_file_name, 'wb') as f:
        f.write(dec_data)

    print('Done!')
