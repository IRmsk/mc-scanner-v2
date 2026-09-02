# -*- coding: utf-8 -*-
"""探测核心：SLP 元数据采集 + 认证模式（在线/破解/白名单）三态检测"""
import json
import socket
import time

from .buffer import (write_varint, write_string, read_string, write_uuid,
                     read_uuid_from_stream, offline_uuid)
from .conn import MCConnection, PROTO_STATE_STATUS, PROTO_STATE_LOGIN
from . import packets

socket_timeout = socket.timeout

# 结果常量
STATE_ONLINE = "online"        # 正版验证服务器（登录返回加密请求）
STATE_CRACKED = "cracked"      # 离线模式服务器（登录直接成功）
STATE_WHITELIST = "whitelist"  # 白名单（登录被拒绝，消息含 whitelist）
STATE_REJECTED = "rejected"    # 登录被拒绝（消息不含 whitelist）
STATE_OFFLINE = "offline"      # 主机不可达/无响应
STATE_ERROR = "error"          # 其它错误


def slp_probe(host: str, port: int, timeout: float = 4.0, retries: int = 2):
    """标准服务器列表 Ping (SLP)：采集 MOTD/版本/人数/延迟。
    返回 dict；失败返回 {'state': 'offline'|'error', ...}"""
    for attempt in range(retries + 1):
        r = _slp_probe_once(host, port, timeout)
        if r.get("state") == "up" or attempt >= retries:
            return r
    return r


def _slp_probe_once(host: str, port: int, timeout: float):
    start = time.time()
    try:
        with MCConnection(host, port, timeout) as conn:
            conn.handshake(protocol=-1, next_state=PROTO_STATE_STATUS)
            conn.send_packet(0x00, b"")  # status request
            pid, payload = conn.recv_packet()
            if pid != 0x00:  # status response
                return {"state": STATE_ERROR, "error": f"意外响应包 0x{pid:02x}"}
            length, offset = 0, 0
            for i in range(5):
                b = payload[offset + i]
                length |= (b & 0x7F) << (7 * i)
                offset += 1
                if not (b & 0x80):
                    break
            jstr = payload[offset:offset + length].decode("utf-8", errors="replace")
            try:
                info = json.loads(jstr)
            except json.JSONDecodeError:
                # 上游 bug 容错：某些服务器(如 Hypixel 部分节点)声明的 JSON 长度
                # 比实际发送少几个字节，导致"截断"。多出的字节在包体尾部，拼上再解析。
                extra = payload[offset + length:]
                if extra:
                    jstr2 = (payload[offset:offset + length] + extra).decode("utf-8", errors="replace")
                    try:
                        info = json.loads(jstr2)
                    except json.JSONDecodeError:
                        raise ValueError("SLP JSON 解析失败")
                else:
                    raise ValueError("SLP JSON 解析失败")
            conn.send_packet(0x01, b"")  # ping
            try:
                pid2, _ = conn.recv_packet()  # pong，用于测延迟
            except Exception:
                pid2 = None
            ping_ms = int((time.time() - start) * 1000)
            version = info.get("version", {})
            players = info.get("players", {})
            return {
                "state": "up",
                "version": version.get("name", ""),
                "proto": version.get("protocol", 0),
                "motd": _motd_text(info.get("description", "")),
                "online": players.get("online", 0),
                "max": players.get("max", 0),
                "sample": players.get("sample", []),
                "ping_ms": ping_ms,
            }
    except (ConnectionError, OSError, TimeoutError, socket_timeout, ValueError, KeyError) as e:
        return {"state": STATE_OFFLINE if _is_offline_err(e) else STATE_ERROR,
                "error": str(e)}


def auth_probe(host: str, port: int, reported_proto: int, username: str = "ScannerTest",
               timeout: float = 4.0, try_versions=None):
    """认证模式检测：登录握手试探。
    返回 dict: state / detected_proto / detail"""
    protos = try_versions or [reported_proto if reported_proto and reported_proto > 0 else None]
    if protos[0] is None:
        # 报告协议未知：按已知档位从新到旧试（多级回退，借鉴 DilanBlue）
        protos = list(reversed(packets.supported_protos()))
    seen = set()
    last_detail = ""
    for proto in protos:
        if proto in seen:
            continue
        seen.add(proto)
        try:
            with MCConnection(host, port, timeout) as conn:
                conn.handshake(protocol=proto, next_state=PROTO_STATE_LOGIN)
                tab = packets.get_table(proto)
                pid = tab["login_start"]
                payload = write_string(username)
                if proto >= 764:  # 1.20.2+ 带 UUID
                    payload += write_uuid(offline_uuid(username))
                conn.send_packet(pid, payload)
                try:
                    resp_id, resp_payload = conn.recv_packet()
                except ConnectionError:
                    # 服务器主动断开：白名单或拒绝
                    last_detail = "连接被关闭"
                    # 尝试读取断开原因（可能已带原因包）
                    return {"state": STATE_WHITELIST, "detected_proto": proto,
                            "detail": "login disconnect"}
                if resp_id == tab["login_success"]:
                    return {"state": STATE_CRACKED, "detected_proto": proto,
                            "detail": "login success (离线/破解服)"}
                if resp_id == tab["login_encryption_begin"]:
                    return {"state": STATE_ONLINE, "detected_proto": proto,
                            "detail": "encryption requested (正版验证)"}
                if resp_id == tab["login_disconnect"]:
                    msg, _ = read_string(resp_payload, 0)
                    low = msg.lower()
                    if "whitelist" in low:
                        return {"state": STATE_WHITELIST, "detected_proto": proto,
                                "detail": f"whitelist: {msg[:80]}"}
                    return {"state": STATE_REJECTED, "detected_proto": proto,
                            "detail": f"rejected: {msg[:80]}"}
                if resp_id == tab["login_compress"]:
                    threshold, _ = read_varint(resp_payload, 0)
                    conn.set_compression(threshold)
                    # 压缩后继续读
                    resp_id, resp_payload = conn.recv_packet()
                    if resp_id == tab["login_success"]:
                        return {"state": STATE_CRACKED, "detected_proto": proto,
                                "detail": "login success (压缩)"}
                    if resp_id == tab["login_encryption_begin"]:
                        return {"state": STATE_ONLINE, "detected_proto": proto,
                                "detail": "encryption requested (压缩)"}
                    if resp_id == tab["login_disconnect"]:
                        msg, _ = read_string(resp_payload, 0)
                        low = msg.lower()
                        return {"state": STATE_WHITELIST if "whitelist" in low else STATE_REJECTED,
                                "detected_proto": proto, "detail": msg[:80]}
                last_detail = f"意外响应 0x{resp_id:02x}"
        except (ConnectionError, OSError, TimeoutError, socket_timeout) as e:
            last_detail = str(e)
    return {"state": STATE_OFFLINE, "detected_proto": None, "detail": last_detail}


def _motd_text(desc):
    if isinstance(desc, str):
        return desc
    if isinstance(desc, dict):
        if "text" in desc:
            return desc["text"]
        extra = desc.get("extra")
        if isinstance(extra, list):
            return "".join(_motd_text(e) for e in extra)
    return str(desc)


def _is_offline_err(e):
    s = str(e).lower()
    return "timed out" in s or "timeout" in s or "refused" in s or "unreachable" in s


try:
    from socket import timeout as socket_timeout
except ImportError:
    class socket_timeout(Exception):
        pass
