#!/usr/bin/python3
"""Generate the original synthetic production-baseline-v1 PCAP corpus."""

from __future__ import annotations

import hashlib
import ipaddress
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TIMESTAMP = 1_786_752_000  # 2026-08-15T00:00:00Z
CLIENT_IP = ipaddress.IPv4Address("192.0.2.10").packed
SERVER_IP = ipaddress.IPv4Address("198.51.100.20").packed
DNS_IP = ipaddress.IPv4Address("198.51.100.53").packed
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")

EXPECTED_SHA256 = {
    "dns-benign.pcap": "eb18fbc2d9f28c9e8c7d31f8bef72af2824cbf3a1aae28cd93ae907766a762a7",
    "dns-scan-positive.pcap": "c9f72b21b6150c6b8c7f4f8aeeb34e0f86eb3af346ac714df84b6c35da2f58e8",
    "http-benign.pcap": "c776fb395609c46770bf53c06b0557316671156ba3565da6257f6835052ce44a",
    "http-exploit-positive.pcap": "c6435f59186b3ded542c82c8507a0b11fd31dd4e126659362a8455ef3c1dc941",
    "tcp-response-positive.pcap": "fc99d8ff5e41b4b70ab1e6840f8a585eb17340b443f9cb6ecf30f7bbef33a46d",
    "tls-benign.pcap": "7ab1194ce26f768d9a41643fc254775d2788e413465743f22ca4331f20cf32f2",
    "udp-remote-positive.pcap": "926c845ec12c7ec8bb0cfd7625616ac095fc757c097166fe9ba1fa39e91eb88b",
}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes, *, to_server: bool = True) -> bytes:
    source, destination = (
        (CLIENT_MAC, SERVER_MAC) if to_server else (SERVER_MAC, CLIENT_MAC)
    )
    return destination + source + struct.pack("!H", 0x0800) + payload


def ipv4(payload: bytes, protocol: int, source: bytes, destination: bytes, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident,
        0x4000,
        64,
        protocol,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def udp(payload: bytes, source: bytes, destination: bytes, source_port: int, destination_port: int) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", source_port, destination_port, length, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 17, length)
    value = checksum(pseudo + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", value) + payload


def tcp(
    payload: bytes,
    source: bytes,
    destination: bytes,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        64240,
        0,
        0,
    )
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    value = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", value) + header[18:] + payload


def tcp_flow(payload: bytes, *, server_payload: bool = False, destination_port: int = 80) -> list[bytes]:
    client_port = 41000
    client_sequence = 1000
    server_sequence = 5000
    frames: list[bytes] = []

    def add(
        data: bytes,
        source: bytes,
        destination: bytes,
        source_port: int,
        destination_port_value: int,
        sequence: int,
        acknowledgement: int,
        flags: int,
        ident: int,
        to_server: bool,
    ) -> None:
        segment = tcp(
            data,
            source,
            destination,
            source_port,
            destination_port_value,
            sequence,
            acknowledgement,
            flags,
        )
        frames.append(
            ethernet(
                ipv4(segment, 6, source, destination, ident),
                to_server=to_server,
            )
        )

    add(b"", CLIENT_IP, SERVER_IP, client_port, destination_port, client_sequence, 0, 0x02, 1, True)
    add(
        b"",
        SERVER_IP,
        CLIENT_IP,
        destination_port,
        client_port,
        server_sequence,
        client_sequence + 1,
        0x12,
        2,
        False,
    )
    add(
        b"",
        CLIENT_IP,
        SERVER_IP,
        client_port,
        destination_port,
        client_sequence + 1,
        server_sequence + 1,
        0x10,
        3,
        True,
    )
    if server_payload:
        add(
            payload,
            SERVER_IP,
            CLIENT_IP,
            destination_port,
            client_port,
            server_sequence + 1,
            client_sequence + 1,
            0x18,
            4,
            False,
        )
    else:
        add(
            payload,
            CLIENT_IP,
            SERVER_IP,
            client_port,
            destination_port,
            client_sequence + 1,
            server_sequence + 1,
            0x18,
            4,
            True,
        )
    return frames


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", 0x4D43, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01"


def tls_client_hello(name: str) -> bytes:
    encoded_name = name.encode("ascii")
    name_entry = b"\x00" + struct.pack("!H", len(encoded_name)) + encoded_name
    server_name = struct.pack("!H", len(name_entry)) + name_entry
    extension = b"\x00\x00" + struct.pack("!H", len(server_name)) + server_name
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x00\x04\xc0\x2f\x00\x9c"
        + b"\x01\x00"
        + struct.pack("!H", len(extension))
        + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def pcap(frames: list[bytes]) -> bytes:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        output.extend(struct.pack("<IIII", TIMESTAMP, index * 1000, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def corpus() -> dict[str, bytes]:
    dns_positive = dns_query("allports.exposed")
    dns_benign = dns_query("example.com")
    udp_positive = b"UK00760S7G10"
    return {
        "dns-scan-positive.pcap": pcap(
            [ethernet(ipv4(udp(dns_positive, CLIENT_IP, DNS_IP, 42000, 53), 17, CLIENT_IP, DNS_IP, 10))]
        ),
        "http-exploit-positive.pcap": pcap(
            tcp_flow(
                b"GET /web.config.i18n.ashx?x=1 HTTP/1.1\r\n"
                b"Host: service.example\r\n"
                b"User-Agent: Meercata-Baseline/1.0\r\n\r\n"
            )
        ),
        "tcp-response-positive.pcap": pcap(
            tcp_flow(b"uid=0(root)\n", server_payload=True, destination_port=65001)
        ),
        "udp-remote-positive.pcap": pcap(
            [
                ethernet(
                    ipv4(
                        udp(udp_positive, CLIENT_IP, SERVER_IP, 43000, 65002),
                        17,
                        CLIENT_IP,
                        SERVER_IP,
                        11,
                    )
                )
            ]
        ),
        "dns-benign.pcap": pcap(
            [ethernet(ipv4(udp(dns_benign, CLIENT_IP, DNS_IP, 42001, 53), 17, CLIENT_IP, DNS_IP, 12))]
        ),
        "http-benign.pcap": pcap(
            tcp_flow(
                b"GET /health HTTP/1.1\r\n"
                b"Host: service.example\r\n"
                b"User-Agent: Meercata-Baseline/1.0\r\n\r\n"
            )
        ),
        "tls-benign.pcap": pcap(tcp_flow(tls_client_hello("service.example"), destination_port=443)),
    }


def main() -> int:
    generated = corpus()
    if set(generated) != set(EXPECTED_SHA256):
        if EXPECTED_SHA256:
            raise SystemExit("generated file inventory differs from the reviewed inventory")
    write = sys.argv[1:] == ["--write"]
    if sys.argv[1:] not in ([], ["--write"]):
        raise SystemExit("usage: generate.py [--write]")
    for name, data in sorted(generated.items()):
        digest = hashlib.sha256(data).hexdigest()
        if write:
            (ROOT / name).write_bytes(data)
        elif not (ROOT / name).is_file() or (ROOT / name).read_bytes() != data:
            raise SystemExit(f"{name} does not reproduce byte-identically")
        expected = EXPECTED_SHA256.get(name)
        if expected is not None and digest != expected:
            raise SystemExit(f"{name} SHA-256 differs from the reviewed hash")
        print(f"{digest}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
