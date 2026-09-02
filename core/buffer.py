# -*- coding: utf-8 -*-
"""Minecraft 协议基础编解码：VarInt / VarLong / String / UUID"""
import struct
import uuid


def write_varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            b |= 0x80
        out.append(b)
        if not value:
            break
    return bytes(out)


def read_varint(data: bytes, offset: int = 0):
    """返回 (value, new_offset)"""
    result = 0
    num_read = 0
    while True:
        if offset + num_read >= len(data):
            raise ValueError("VarInt 数据不完整")
        byte = data[offset + num_read]
        result |= (byte & 0x7F) << (7 * num_read)
        num_read += 1
        if not (byte & 0x80):
            break
        if num_read > 5:
            raise ValueError("VarInt 过长")
    if result >= (1 << 31):
        result -= (1 << 32)
    return result, offset + num_read


def read_varint_from_stream(stream) -> int:
    result = 0
    num_read = 0
    while True:
        if hasattr(stream, "recv"):
            b = stream.recv(1)
        else:
            b = stream.read(1)
        if not b:
            raise ConnectionError("连接已关闭")
        byte = b[0]
        result |= (byte & 0x7F) << (7 * num_read)
        num_read += 1
        if not (byte & 0x80):
            break
        if num_read > 5:
            raise ValueError("VarInt 过长")
    if result >= (1 << 31):
        result -= (1 << 32)
    return result


def write_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return write_varint(len(encoded)) + encoded


def read_string(data: bytes, offset: int = 0):
    length, offset = read_varint(data, offset)
    if offset + length > len(data):
        raise ValueError("字符串数据不完整")
    return data[offset:offset + length].decode("utf-8", errors="replace"), offset + length


def read_string_from_stream(stream) -> str:
    length = read_varint_from_stream(stream)
    data = _read_n(stream, length)
    if len(data) != length:
        raise ConnectionError("字符串被截断")
    return data.decode("utf-8", errors="replace")


def _read_n(stream, n):
    data = b""
    while len(data) < n:
        c = stream.recv(n - len(data))
        if not c:
            raise ConnectionError("连接已关闭")
        data += c
    return data


def write_uuid(u: uuid.UUID) -> bytes:
    return u.int.to_bytes(16, "big")


def read_uuid_from_stream(stream) -> uuid.UUID:
    data = _read_n(stream, 16)
    if len(data) != 16:
        raise ConnectionError("UUID 被截断")
    return uuid.UUID(int=int.from_bytes(data, "big"))


def offline_uuid(username: str) -> uuid.UUID:
    """离线模式玩家 UUID 标准生成方式（Online UUID v3）"""
    return uuid.uuid3(uuid.NAMESPACE_OID, f"OfflinePlayer:{username}")
