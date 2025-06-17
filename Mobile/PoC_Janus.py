#!/usr/bin/python3

import sys
import struct
import hashlib
from zlib import adler32

def update_checksum(data):
    m = hashlib.sha1()
    m.update(data[32:])
    data[12:12+20] = m.digest()

    v = adler32(bytes(data[12:])) & 0xffffffff
    data[8:12] = struct.pack("<L", v)

def main():
    if len(sys.argv) != 4:
        print("usage: %s dex apk out_apk" % sys.argv[0])
        return

    _, dex, apk, out_apk = sys.argv

    with open(dex, 'rb') as f:
        dex_data = bytearray(f.read())
    dex_size = len(dex_data)

    with open(apk, 'rb') as f:
        apk_data = bytearray(f.read())
    cd_end_addr = apk_data.rfind(b'\x50\x4b\x05\x06')
    if cd_end_addr == -1:
        raise ValueError("Invalid APK: End of central directory not found.")
    cd_start_addr = struct.unpack("<L", apk_data[cd_end_addr+16:cd_end_addr+20])[0]
    apk_data[cd_end_addr+16:cd_end_addr+20] = struct.pack("<L", cd_start_addr + dex_size)

    pos = cd_start_addr
    while pos < cd_end_addr:
        if apk_data[pos:pos+4] != b'\x50\x4b\x01\x02':
            break  # Invalid central directory entry
        # Update local header offset
        offset = struct.unpack("<L", apk_data[pos+42:pos+46])[0]
        apk_data[pos+42:pos+46] = struct.pack("<L", offset + dex_size)
        # Calculate entry length
        file_name_len = struct.unpack("<H", apk_data[pos+28:pos+30])[0]
        extra_field_len = struct.unpack("<H", apk_data[pos+30:pos+32])[0]
        file_comment_len = struct.unpack("<H", apk_data[pos+32:pos+34])[0]
        entry_len = 46 + file_name_len + extra_field_len + file_comment_len
        pos += entry_len

    out_data = dex_data + apk_data
    # Correct DEX file size in header (offset 32)
    out_data[32:36] = struct.pack("<L", dex_size)
    update_checksum(out_data)

    with open(out_apk, "wb") as f:
        f.write(out_data)

    print('%s generated' % out_apk)

if __name__ == '__main__':
    main()