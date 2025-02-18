#!/usr/bin/python3
import sys
from struct import pack

if (len(sys.argv) <= 1):
  print('Usage : python3 ' + sys.argv[0] + ' sid' + "\n")
  exit(0)
sid = sys.argv[1]
print(f'[+] SID : {sid}')
items = sid.split('-')

revision = pack('B',int(items[1]))
dashNumber = pack('B',len(items) - 3)
identifierAuthority = b'\x00\x00' + pack('>L',int(items[2]))

subAuthority= b''
for i in range(len(items) - 3):
  subAuthority += pack('<L', int(items[i+3]))

hex_sid = revision + dashNumber + identifierAuthority + subAuthority
result = ('0x' + ''.join('{:02X}'.format(b) for b in hex_sid))
print(f'[+] Result : {result}')