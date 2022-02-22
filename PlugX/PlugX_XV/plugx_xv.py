import struct
import lznt1dec


def decrypt1(data, n_add, start_pos):
    """PlugX XV decrypt data universal function (variant 1)"""

    dec_data = b''

    n, = struct.unpack_from('<L', data, 0)

    for i in range(start_pos, len(data)):
        n = ((n << 7) - (n >> 3) + (i - start_pos) + n_add) & 0xFFFFFFFF
        b = (data[i] ^ (n >> 24) ^ (n >> 16) ^ (n >> 8) ^ n) & 0xFF
        dec_data += bytes([b])

    return dec_data


convolute_dword = lambda n: (((n - (n >> 8)) ^ (n >> 16)) - (n >> 24)) & 0xFF


def decrypt2(data, n1_xor, n2_xor, n1_add, n2_sub):
    """PlugX XV decrypt data universal function (variant 2)"""

    dec_data = b''

    n, = struct.unpack_from('<L', data, 0)
    if n1_xor == 0:
        n1 = n
        n2 = n2_xor
    else:
        n1 = n ^ n1_xor
        n2 = n ^ n2_xor

    for i in range(4, len(data)):
        n1 = (n1 + n1_add) & 0xFFFFFFFF
        n2 = (n2 - n2_sub) & 0xFFFFFFFF
        b = data[i] ^ convolute_dword(convolute_dword(n1) ^ n2)
        dec_data += bytes([b])

    return dec_data


PLUGX_XV_DECRYPT_SETTINGS = {
    # (type, constants)

    # Version: 20130524
    # RasTls.dll/RasTls.dll.msc
    # Version: 20130810
    # AShldRes.dll/AShldRes.DLL.asr
    # ushata.dll/ushata.dll.avp
    20130524: ( 0, 0x713A8FC1 ),

    # Version: 20140307
    # SetupEngine.dll/System.bin
    20140307: ( 0, 0x20140307 ),

    # Version: 20140428
    # ushata.dll/ushata.door.open
    # McAltLib.dll/mcs.cvt
    20140428: ( 0, 0x20140428 ),

    # Version: 20140509
    # splash_screen.dll/splash_screen.dyload
    20140509: ( 0, 0x20140509 ),

    # Version: 20140609
    # mcutil.dll/mcutil.dll.bbc
    # aross.dll/kor_boot.ttf
    # aross.dll/wintask.log
    # aross.dll/aross.pig
    # Winssec.exe/Winssec.cfg
    # winkit.exe/winkit.cfg
    # lscsvr.exe/lscsvr.cfg
    # wrap.exe/setting.ini
    # unitsvc.exe/unitsvc.cfg
    # rnapp.exe/rnapp.cfg
    # Csrsec.exe/Csrsec.cfg
    20140609: ( 1, ( 0, 0x20140609, 0x0C34F, 0x7525 ) ),

    # Version: 20140613
    # dbghelp.dll/moic.exe.dat
    # dbghelp.dll/winhlp32.exe.dat
    # McUtil.dll/McUtil.dll.mc
    # RasTls.dll/set.conf
    # msi.dll/msi.dll.mov
    20140613: ( 1, ( 0, 0x20140613, 0x0C34F, 0x7525 ) ),

    # Version: 20140719
    # splash_screen.dll/splash_screen.dll.sky
    # aross.dll/aross.pig
    # symerr.exe/ccL110U.dll
    # po_x64.dll
    # lsm.exe
    # dwm.exe
    # depends.exe
    20140719: ( 1, ( 0x13352AF, 0x0A7, 0x6FD, 0x305B ) ),

    # Version: 20140818
    # mcutil.dll/mcf.ep
    20140818: ( 1, ( 0x1335312, 0x47, 0x2CF, 0x1EDD ) ),

    # Version: 20141028
    # fslapi.dll/fslapi.dll.gui
    20141028: ( 1, ( 0x13353E4, 0x139, 0x655, 0x6697 ) ),
                                                    
    # Version: 20141216
    # ssMUIDLL.dll/ssMUIDLL.dll.conf
    20141216: ( 1, ( 0xEF, 0xA3D, 0x5347, 0x13354A0 ) ),

    # Version: 20150108
    # SXLOC.dll/SXLOC.ZAP
    20150108: ( 1, ( 0x133775C, 0x38F, 0xB5D, 0x6157 ) ),

    # Version: 20150202
    # scansts.dll/QuickHeal
    20150202: ( 1, ( 0x13377BA, 0x1B1, 0x10F1, 0x70C3 ) ),

    # Version: 20150416
    # rapi.dll/rapi.dll.rap
    20150416: ( 1, ( 0x1337890, 0x5BF1, 0x5BF3, 0x5BFD ) ),
}


def decrypt_data(ver, data):
    """PlugX XV decrypt data"""

    decrypt_settings = PLUGX_XV_DECRYPT_SETTINGS.get(ver)
    if decrypt_settings is None:
        raise ValueError('Unknown PlugX XV version')

    if decrypt_settings[0] == 0:
        return decrypt1(data, decrypt_settings[1], 4)

    return decrypt2(data, *decrypt_settings[1])


def decrypt_cfg(ver, data, size_present=True):
    """
    PlugX XV decrypt configuration data
    For type=1:
    size_present=False (if PlugX XV saved the configuration data to a file)
    """

    decrypt_settings = PLUGX_XV_DECRYPT_SETTINGS.get(ver)
    if decrypt_settings is None:
        raise ValueError('Unknown PlugX XV version')

    if decrypt_settings[0] == 0:
        return decrypt1(data, decrypt_settings[1], 0)

    if size_present:
        size, = struct.unpack_from('<L', data, 0)
        enc_data = data[4 : 4 + size]
    else:
        enc_data = data
    dec_data = decrypt2(enc_data, *decrypt_settings[1])
    return lznt1dec.decompress(dec_data[4:])


if __name__ == '__main__':
    import sys
    import io

    if len(sys.argv) != 3:
        print('Usage: '+ sys.argv[0] + ' version filename')
        exit(0)

    ver = int(sys.argv[1])
    file_name = sys.argv[2]

    with io.open(file_name, 'rb') as f:
        data = f.read()

    dec_data = decrypt_data(ver, data)

    new_file_name = file_name + '.dec'
    with io.open(new_file_name, 'wb') as f:
        f.write(dec_data)

    print('Done!')
