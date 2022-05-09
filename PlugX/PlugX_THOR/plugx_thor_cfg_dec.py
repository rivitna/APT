import sys
import io
import plugx_thor


if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

file_name = sys.argv[1]

with io.open(file_name, 'rb') as f:
    data = f.read()

dec_data = plugx_thor.decrypt1(data)

new_file_name = file_name + '.dec'
with io.open(new_file_name, 'wb') as f:
    f.write(dec_data)

print('Done!')
