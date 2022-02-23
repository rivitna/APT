import io
import os
from x64dbgpy.pluginsdk import *


def x64dbg_save_data(dest_dir, file_name, addr, size):
    """Save data to file"""

    # Read data
    read_bytes = bytearray(size)
    result, read_size = x64dbg.Memory_Read(addr, read_bytes, size)

    # Save data to file
    with io.open(os.path.join(dest_dir, file_name), 'wb') as f:
        f.write(read_bytes[:read_size])


def x64dbg_run_to_addr(addr):
    """Run to specifed address"""

    x64dbg.SetHardwareBreakpoint(addr, x64dbg.HardwareExecute)
    x64dbg.Run()
    x64dbg.DeleteHardwareBreakpoint(addr)


def x64dbg_get_ep_addr(mod_addr):
    """Get PE module entry point address"""

    nt_hdr_addr = mod_addr + x64dbg.ReadDword(mod_addr + 0x3C)

    num_sections = x64dbg.ReadWord(nt_hdr_addr + 6)
    ep_rva = x64dbg.ReadDword(nt_hdr_addr + 0x28)
    opt_hdr_size = x64dbg.ReadWord(nt_hdr_addr + 0x14)
    nt_hdr_size = 4 + 0x14 + opt_hdr_size
    section_hdr_addr = nt_hdr_addr + nt_hdr_size

    for i in range(num_sections):

        s_vsize = x64dbg.ReadWord(section_hdr_addr + 8)
        s_rva = x64dbg.ReadWord(section_hdr_addr + 12)
        s_psize = x64dbg.ReadWord(section_hdr_addr + 16)
        s_pos = x64dbg.ReadWord(section_hdr_addr + 20)

        if (s_pos != 0) and (ep_rva >= s_rva):
            offset = ep_rva - s_rva
            if (offset < min(s_vsize, s_psize)):
                return (mod_addr + s_pos + offset)

        section_hdr_addr += 0x28

    return 0


#
# Main
#

dest_dir = os.path.abspath(os.path.dirname(__file__))

Run()

# Break on RtlDecompressBuffer
addr = ResolveLabel('RtlDecompressBuffer')
if addr == 0:
    raise Exception('Failed to resolve RtlDecompressBuffer.')
x64dbg_run_to_addr(addr)

addr = x64dbg.GetESP()

# Check COMPRESSION_FORMAT_LZNT1
if x64dbg.ReadDword(addr + 4) != 2:
    raise Exception('Invalid compression format.')

# Save payload
payload_addr = x64dbg.ReadPtr(addr + 8)
payload_size = x64dbg.ReadPtr(addr + 12)
print('Payload address: %08X' % payload_addr)
print('Payload size: %d' % payload_size)
x64dbg.StepOut()
x64dbg_save_data(dest_dir, 'payload.dll_', payload_addr, payload_size)

# Get payload entry point address
ep_addr = x64dbg_get_ep_addr(payload_addr)
if ep_addr == 0:
    raise Exception('Couldn\'t get payload entry point address.')
print('Payload entry point address: %08X' % ep_addr)

# Write int 3 to payload entry point
x64dbg.WriteByte(ep_addr, 0xCC)

Run()

addr = x64dbg.GetESP()
payload_base = x64dbg.ReadPtr(addr + 4)
print('Payload base address: %08X' % payload_base)

# PlugX payload signature
plugx_sign = x64dbg.ReadDword(payload_base)
print('Payload signature: %08X' % plugx_sign)

# Payload params
payload_param_addr = x64dbg.ReadPtr(addr + 12)
print('Payload param address: %08X' % payload_param_addr)

# Shellcode
shellcode_addr = x64dbg.ReadPtr(payload_param_addr)
shellcode_size = x64dbg.ReadPtr(payload_param_addr + 4)
print('Shellcode address: %08X' % shellcode_addr)
print('Shellcode size: %d' % shellcode_size)
x64dbg_save_data(dest_dir, 'shellcode.bin', shellcode_addr, shellcode_size)

# Packed payload
packed_payload_addr = x64dbg.ReadPtr(payload_param_addr + 8)
packed_payload_size = x64dbg.ReadPtr(payload_param_addr + 0xC)
print('Packed payload address: %08X' % packed_payload_addr)
print('Packed payload size: %d' % packed_payload_size)
x64dbg_save_data(dest_dir, 'payload.pak',
                 packed_payload_addr, packed_payload_size)

# Configuration data
cfg_addr = x64dbg.ReadPtr(payload_param_addr + 0x10)
cfg_size = x64dbg.ReadPtr(payload_param_addr + 0x14)
print('Config address: %08X' % cfg_addr)
print('Config size: %d' % cfg_size)
x64dbg_save_data(dest_dir, 'config.enc', cfg_addr, cfg_size)
