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

# size_present=False (if PlugX XV saved the configuration data to a file)
cfg_data = plugx_xv.decrypt_cfg(ver, data, True)

new_file_name = file_name + '.dec'
with io.open(new_file_name, 'wb') as f:
    f.write(cfg_data)

print('Done!')
