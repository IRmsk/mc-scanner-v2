# -*- coding: utf-8 -*-
"""MC TCP 连接：收发包、长度前缀、可选压缩"""
import socket
import zlib
from .buffer import write_varint, read_varint_from_stream, write_string

PROTO_STATE_HANDSHAKE = 0
PROTO_STATE_STATUS = 1
PROTO_STATE_LOGIN = 2
PROTO_STATE_CONFIGURATION = 3
PROTO_STATE_PLAY = 4


class MCConnection:
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.compression_threshold = -1
        self.state = PROTO_STATE_HANDSHAKE

    # ---- 发送 ----
    def send_packet(self, packet_id: int, payload: bytes):
        body = write_varint(packet_id) + payload
        if self.compression_threshold >= 0:
            if len(body) >= self.compression_threshold:
                compressed = zlib.compress(body)
                packet = write_varint(len(body)) + compressed
            else:
                packet = write_varint(0) + body
            self.sock.sendall(write_varint(len(packet)) + packet)
        else:
            self.sock.sendall(write_varint(len(body)) + body)

    # ---- 接收 ----
    def recv_packet(self):
        length = read_varint_from_stream(self.sock)
        if length <= 0 or length > 2 * 1024 * 1024:
            raise ConnectionError(f"非法包长度: {length}")
        data = b""
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("连接在读取中关闭")
            data += chunk
        if self.compression_threshold >= 0:
            ulen, offset = self._read_varint_at(data, 0)
            if ulen > 0:
                body = zlib.decompress(data[offset:])
            else:
                body = data[offset:]
        else:
            body = data
        packet_id, off = self._read_varint_at(body, 0)
        return packet_id, body[off:]

    @staticmethod
    def _read_varint_at(data, offset):
        result, num_read = 0, 0
        while True:
            byte = data[offset + num_read]
            result |= (byte & 0x7F) << (7 * num_read)
            num_read += 1
            if not (byte & 0x80):
                break
        if result >= (1 << 31):
            result -= (1 << 32)
        return result, offset + num_read

    # ---- 握手 ----
    def handshake(self, protocol: int, next_state: int):
        payload = write_varint(protocol) + write_string(self.host) + \
            self.port.to_bytes(2, "big") + write_varint(next_state)
        self.send_packet(0x00, payload)
        self.state = next_state

    def set_compression(self, threshold: int):
        self.compression_threshold = threshold

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
