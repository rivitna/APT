import sys
import io
import struct


CFG_FIELD_UNKNOWN = 0
CFG_FIELD_STRING = 1
CFG_FIELD_NUMBER = 2
CFG_FIELD_CONN_INFO = 3

CFG_FIELD_TYPE_LIST = {
    0x0145: ('Encryption key', CFG_FIELD_STRING),
    0x018C: ('C&C max index', CFG_FIELD_NUMBER),
    0x0190: ('C&C', CFG_FIELD_CONN_INFO),
    0x02C1: ('Proxy max index', CFG_FIELD_NUMBER),
    0x02C5: ('Proxy', CFG_FIELD_CONN_INFO),
    0x03FB: ('Mutex name', CFG_FIELD_STRING),
    0x040F: ('Active Setup reg value name', CFG_FIELD_STRING),
    0x0418: ('Default browser path reg key', CFG_FIELD_STRING),
    0x0456: ('Active Setup reg key', CFG_FIELD_STRING),
    0x0AFA: ('Campaign Id', CFG_FIELD_STRING),
    0x0BF9: ('Group Id', CFG_FIELD_STRING),
    0x0D09: ('HKLM/HKCU autorun reg key flag', CFG_FIELD_NUMBER),
    0x0E12: ('Autorun reg value name', CFG_FIELD_STRING),
    0xEB00: ('Unknown_EB00', CFG_FIELD_STRING),
    0xEC00: ('Unknown_EC00', CFG_FIELD_STRING),
    0xED00: ('Unknown_ED00', CFG_FIELD_STRING),
    0xEF7C: ('Unknown_EF7C', CFG_FIELD_NUMBER),
    0xEF8C: ('Unknown_EF8C', CFG_FIELD_NUMBER),
    0xEF90: ('Unknown_EF90', CFG_FIELD_NUMBER),
    0xEF94: ('Unknown_EF94', CFG_FIELD_NUMBER),
    0xEFF8: ('Unknown_EFF8', CFG_FIELD_NUMBER),
    0xEFFC: ('Unknown_EFFC', CFG_FIELD_NUMBER)
}


GET_CFG_DATA_CODE = b'\xE8\0\0\0\0'


def extract_cfg_data(data):
    pos = 0
    while True:
        # call $+5
        pos = data.find(GET_CFG_DATA_CODE, pos)
        if (pos < 0):
            break
        pos += len(GET_CFG_DATA_CODE)
        # pop esi
        if ((data[pos] & 0xF0) != 0x50):
            continue
        # add esi, cfg_rel_offset
        if ((data[pos + 1] == 0x81) and ((data[pos + 2] & 0xF0) == 0xC0)):
            cfg_rel_ofs, = struct.unpack_from('<L', data, pos + 3)
            if (pos + cfg_rel_ofs) < len(data):
                return data[pos + cfg_rel_ofs:]
    return None

def print_cfg_field(fld_id, fld_len, fld_val):
    fld_type_entry = CFG_FIELD_TYPE_LIST.get(fld_id)
    if (fld_type_entry is None):
        print('Unknown field id (%04X).' % fld_id)
        return

    if (fld_type_entry[1] == CFG_FIELD_STRING):        
        print('%s: \"%s\"' % (fld_type_entry[0], fld_val.decode()))

    elif (fld_type_entry[1] == CFG_FIELD_NUMBER):
        t = None
        if (fld_len == 1):
            t = 'B'
        elif (fld_len == 2):
            t = 'H'
        elif (fld_len == 4):
            t = 'L'
        elif (fld_len == 8):
            t = 'Q'
        if (t is not None):
            val_num, = struct.unpack('<' + t, fld_val)
            fld_fmt = '%s: %0' + str(fld_len << 1) + 'X'
            print(fld_fmt % (fld_type_entry[0], val_num))
        else:  
            print('Invalid field \"%s\" data size (%d).' %
                      (fld_type_entry[0], fld_len))

    elif (fld_type_entry[1] == CFG_FIELD_CONN_INFO):
        pos = 0
        c2c_num = 0
        while (pos < len(fld_val)):
            c2c_addr_len = fld_val[pos]
            pos += 1
            c2c_addr = fld_val[pos : pos + c2c_addr_len].decode()
            pos += c2c_addr_len
            c2c_type = fld_val[pos]
            pos += 1
            c2c_port, = struct.unpack_from('<H', fld_val, pos)
            pos += 2
            print('%s[%d]: (%d) \"%s:%d\"' %
                      (fld_type_entry[0], c2c_num, c2c_type, c2c_addr, c2c_port))
            c2c_num += 1

    elif (fld_type_entry[1] == CFG_FIELD_UNKNOWN):
        print('%s: ? (%d bytes)' % (fld_type_entry[0], fld_len))


if len(sys.argv) != 2:
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

file_name = sys.argv[1]

with io.open(file_name, 'rb') as f:
    data = f.read()

cfg_data = extract_cfg_data(data)

del data

if (cfg_data is None):
    raise Exception('Configuration data not found.')

new_file_name = file_name + '.cfg'
with io.open(new_file_name, 'wb') as f:
    f.write(cfg_data)

pos = 0
while (pos < len(cfg_data)):
    fld_id, fld_len = struct.unpack_from('<2H', cfg_data, pos)
    if (fld_id == 0):
        pos += 2
        break

    pos += 4
    print_cfg_field(fld_id, fld_len, cfg_data[pos : pos + fld_len])
    pos += fld_len
