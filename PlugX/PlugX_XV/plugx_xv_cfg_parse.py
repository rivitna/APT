import sys
import io
import struct
from collections import namedtuple


C2C_ENTRY_SIZE = 0x44
URL_ENTRY_SIZE = 0x80
PROXY_ENTRY_SIZE = 0xC4
PROXY_NUM_ENTRIES = 4
STR_VALUE_SIZE = 512

cfg_parse_params = namedtuple('cfg_parse_params',
[
    'c2c_pos',
    'c2c_num_entries',
    'url_num_entries',
    'num_target_processes',
    'num_uacbypass_processes',
    'screenshot_present'
])

CFG_PARSE_CASES = {
    7448 : cfg_parse_params(c2c_pos = 0x2EC,
                            c2c_num_entries = 4,
                            url_num_entries = 4,
                            num_target_processes = 1,
                            num_uacbypass_processes = 0,
                            screenshot_present = False),
    9536 : cfg_parse_params(c2c_pos = 0x2EC,
                            c2c_num_entries = 4,
                            url_num_entries = 4,
                            num_target_processes = 4,
                            num_uacbypass_processes = 0,
                            screenshot_present = True),
    11608 : cfg_parse_params(c2c_pos = 0x2EC,
                             c2c_num_entries = 4,
                             url_num_entries = 4,
                             num_target_processes = 4,
                             num_uacbypass_processes = 4,
                             screenshot_present = True),
    13988 : cfg_parse_params(c2c_pos = 0x2E0,
                             c2c_num_entries = 16,
                             url_num_entries = 16,
                             num_target_processes = 4,
                             num_uacbypass_processes = 4,
                             screenshot_present = True)
}


def rtrim(s):
    ln = s.find('\0')
    if (ln == -1):
        return s
    return s[:ln]


def read_wide_str_and_convert(data, pos, size):
    s = data[pos : pos + size]
    return rtrim(s.decode('utf-16'))


def get_reg_root_key_name(hkey):
    if (hkey == 0x80000000):
        return "HKCR"
    elif (hkey == 0x80000001):
        return "HKCU"
    elif (hkey == 0x80000002):
        return "HKLM"
    elif (hkey == 0x80000003):
        return "HKU"
    elif (hkey == 0x80000005):
        return "HKCC"
    else:
        return hex(hkey)


def print_c2c_str(data, pos, index):
    net_type, port = struct.unpack_from("<HH", data, pos)
    addr = rtrim(data[pos + 4 : pos + 4 + 0x40].decode())
    if (len(addr) == 0):
        print('C&C[' + str(index) + ']:')
    else:
        print('C&C[{:d}]: ({:d}) "{}:{:d}"'.format(index, net_type, addr, port))


def print_url_str(data, pos, index):
    url = rtrim(data[pos : pos + URL_ENTRY_SIZE].decode())
    if (len(url) == 0):
        print('URL[' + str(index) + ']:')
    else:
        print('URL[{:d}]: "{}"'.format(index, url))


def print_proxy_params(data, pos, index):
    proxy_type, port = struct.unpack_from("<HH", data, pos)
    addr = rtrim(data[pos + 4 : pos + 0x44].decode())
    user = rtrim(data[pos + 0x44 : pos + 0x84].decode())
    pwd = rtrim(data[pos + 0x84 : pos + 0xC4].decode())
    if (len(addr) == 0):
        print('Proxy[' + str(index) + ']:')
    else:
        print('Proxy[{:d}]: ({:d}) "{}:{:d}" User: "{}" Password: "{}"'.format(index,
                                                                               proxy_type,
                                                                               addr,
                                                                               port,
                                                                               user,
                                                                               pwd))


def print_cfg_str_val(data, pos, name):
    s = read_wide_str_and_convert(data, pos, STR_VALUE_SIZE)
    print(name + ': "' + s + '"')


def print_cfg_dword_val(data, pos, name):
    val, = struct.unpack_from("<L", data, pos)
    print(name + ': ' + str(val))


if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

file_name = sys.argv[1]

with io.open(file_name, 'rb') as f:
    data = f.read()

parse_params = CFG_PARSE_CASES.get(len(data))
if (parse_params is None):
    print('Error: Unsupported PlugX configuration file.')
    sys.exit(0)

pos = parse_params.c2c_pos

for i in range(parse_params.c2c_num_entries):
    print_c2c_str(data, pos + i * C2C_ENTRY_SIZE, i)
pos += parse_params.c2c_num_entries * C2C_ENTRY_SIZE

for i in range(parse_params.url_num_entries):
    print_url_str(data, pos + i * URL_ENTRY_SIZE, i)
pos += parse_params.url_num_entries * URL_ENTRY_SIZE

for i in range(PROXY_NUM_ENTRIES):
    print_proxy_params(data, pos + i * PROXY_ENTRY_SIZE, i)
pos += PROXY_NUM_ENTRIES * PROXY_ENTRY_SIZE

print_cfg_dword_val(data, pos, 'Persistence')
pos += 4
print_cfg_str_val(data, pos, 'Install path')
pos += STR_VALUE_SIZE
print_cfg_str_val(data, pos, 'Service name')
pos += STR_VALUE_SIZE
print_cfg_str_val(data, pos, 'Service display name')
pos += STR_VALUE_SIZE
print_cfg_str_val(data, pos, 'Service description')
pos += STR_VALUE_SIZE
hkey, = struct.unpack_from("<L", data, pos)
print('Autorun reg key: ' + get_reg_root_key_name(hkey))
pos += 4
print_cfg_str_val(data, pos, 'Autorun reg key path')
pos += STR_VALUE_SIZE
print_cfg_str_val(data, pos, 'Autorun reg value name')
pos += STR_VALUE_SIZE

if (parse_params.num_target_processes > 0):
    print_cfg_dword_val(data, pos, 'Process injection')
    pos += 4
    for i in range(parse_params.num_target_processes):
        print_cfg_str_val(data, pos, 'Target process[' + str(i) + ']')
        pos += STR_VALUE_SIZE
if (parse_params.num_uacbypass_processes > 0):
    print_cfg_dword_val(data, pos, 'UAC Bypass process injection')
    pos += 4
    for i in range(parse_params.num_uacbypass_processes):
        print_cfg_str_val(data, pos, 'UAC Bypass target process[' + str(i) + ']')
        pos += STR_VALUE_SIZE

print_cfg_str_val(data, pos, 'Actor Id')
pos += STR_VALUE_SIZE
print_cfg_str_val(data, pos, 'Target Id')
pos += STR_VALUE_SIZE
print_cfg_str_val(data, pos, 'Mutex name')
pos += STR_VALUE_SIZE

if parse_params.screenshot_present:
    print_cfg_dword_val(data, pos, 'Screenshots')
    pos += 4
    print_cfg_dword_val(data, pos, 'Screenshot frequency (secs)')
    pos += 4
    print_cfg_dword_val(data, pos, 'Screenshot zoom')
    pos += 4
    print_cfg_dword_val(data, pos, 'Screenshot color bits')
    pos += 4
    print_cfg_dword_val(data, pos, 'Screenshot quality')
    pos += 4
    print_cfg_dword_val(data, pos, 'Screenshot remain days')
    pos += 4
    print_cfg_str_val(data, pos, 'Sckreenshot save directory')
    pos += STR_VALUE_SIZE
