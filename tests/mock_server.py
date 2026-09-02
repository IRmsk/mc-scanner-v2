# -*- coding: utf-8 -*-
"""独立 mock MC 服务器：用于端到端测试。

重要：本文件的包 ID 为官方 protocol.json 手工核对的常量，绝不 import 实现的
packet_ids.py —— 与实现分离，才能测出"假成功"类 bug。

支持三种认证模式：
  online   -> 登录回 encryption_begin（正版验证）
  cracked  -> 登录回 login_success（离线/破解）
  whitelist-> 登录回 disconnect（含 whitelist 关键词）
"""
import json
import socket
import threading
import struct
import time


# ---- 官方协议常量（login 阶段，1.20.2-1.21.11 一致）----
LID_DISCONNECT = 0x00
LID_ENCRYPTION = 0x01
LID_SUCCESS = 0x02
SID_STATUS = 0x00
SID_PING = 0x01

# 官方 play/config 阶段包 ID（按版本，来自 PrismarineJS/minecraft-data，独立于实现）
# chat = play toServer chat_message; cfg_finish_cb = config toClient finish_configuration
# cfg_known_packs = 配置阶段是否要求 select_known_packs; play_ka = play toClient keep_alive
OFFICIAL = {
    764: {"chat": 0x05, "cfg_finish_cb": 0x02, "cfg_known_packs": False, "play_ka": 0x24},
    767: {"chat": 0x06, "cfg_finish_cb": 0x03, "cfg_known_packs": True,  "play_ka": 0x26},
    771: {"chat": 0x08, "cfg_finish_cb": 0x03, "cfg_known_packs": True,  "play_ka": 0x26},
}


def _varint(v):
    v &= 0xFFFFFFFF
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            b |= 0x80
        out.append(b)
        if not v:
            break
    return bytes(out)


def _packet(packet_id, payload=b""):
    body = _varint(packet_id) + payload
    return _varint(len(body)) + body


def _string(s):
    b = s.encode("utf-8")
    return _varint(len(b)) + b


def _read_varint(stream):
    r = 0
    for i in range(5):
        b = stream.recv(1)
        if not b:
            raise ConnectionError
        r |= (b[0] & 0x7F) << (7 * i)
        if not (b[0] & 0x80):
            return r
    raise ValueError


def _read_exact(stream, n):
    data = b""
    while len(data) < n:
        c = stream.recv(n - len(data))
        if not c:
            raise ConnectionError
        data += c
    return data


class MockServer:
    def __init__(self, proto=771, version="1.21.6", auth="cracked",
                 motd="Mock Server", online=2, maxp=20, full_login=False):
        self.proto = proto
        self.version = version
        self.auth = auth
        self.motd = motd
        self.online, self.maxp = online, maxp
        self.full_login = full_login
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(8)
        self.port = self.sock.getsockname()[1]
        self.received = []  # 记录收到的 (阶段, 包ID, payload)
        self.chat_messages = []
        self.login_payloads = []
        self._stop = False
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(6)
            # handshake
            _read_varint(conn)
            _read_varint(conn)  # id 0x00
            _read_varint(conn)  # protocol
            slen = _read_varint(conn)
            _read_exact(conn, slen)
            _read_exact(conn, 2)  # port
            next_state = _read_varint(conn)
            if next_state == 1:
                self._handle_status(conn)
            elif next_state == 2:
                self._handle_login(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_status(self, conn):
        _read_varint(conn)
        _read_varint(conn)  # status request 0x00
        info = {
            "version": {"name": self.version, "protocol": self.proto},
            "players": {"online": self.online, "max": self.maxp,
                        "sample": [{"name": "mock_user", "id": "00000000-0000-0000-0000-000000000001"}]},
            "description": {"text": self.motd},
        }
        js = json.dumps(info, ensure_ascii=False).encode("utf-8")
        conn.sendall(_packet(SID_STATUS, _varint(len(js)) + js))
        # 等待 ping
        try:
            _read_varint(conn)
            _read_varint(conn)
            data = _read_exact(conn, 8)
            conn.sendall(_packet(SID_PING, data))
        except Exception:
            pass

    def _handle_login(self, conn):
        _read_varint(conn)
        _read_varint(conn)  # login start 0x00
        ulen = _read_varint(conn)
        username = _read_exact(conn, ulen).decode("utf-8", "replace")
        _read_exact(conn, 16)  # 1.20.2+ login start 带 UUID
        self.received.append(("login_start", username))
        self.login_payloads.append(username)
        if self.auth == "cracked":
            # login success: UUID(16) + username
            payload = bytes.fromhex("00000000000000000000000000000001") + _string(username)
            conn.sendall(_packet(LID_SUCCESS, payload))
        elif self.auth == "online":
            # encryption begin: server_id("") + public key + verify token
            server_id = _string("")
            pubkey = _varint(2) + b"\x00\x01"
            token = _varint(4) + b"\x11\x22\x33\x44"
            conn.sendall(_packet(LID_ENCRYPTION, server_id + pubkey + token))
        elif self.auth == "whitelist":
            reason = _string('{"text":"You are not whitelisted on this server!"}')
            conn.sendall(_packet(LID_DISCONNECT, reason))
        elif self.auth == "reject":
            reason = _string('{"text":"Connection throttled"}')
            conn.sendall(_packet(LID_DISCONNECT, reason))
        if self.auth == "cracked" and self.full_login:
            self._handle_config_play(conn, username)
        time.sleep(0.2)

    def _handle_config_play(self, conn, username):
        """完整流程（符合真实 vanilla/Paper）：服务端发 known_packs 询问 →
        客户端回 known_packs + finish → 服务端回 finish → play → 收聊天"""
        off = OFFICIAL.get(self.proto, OFFICIAL[767])
        def read_packet():
            length = _read_varint(conn)
            data = _read_exact(conn, length)
            pid, i = 0, 0
            while True:
                b = data[i]
                pid |= (b & 0x7F) << (7 * i)
                i += 1
                if not (b & 0x80):
                    break
            return pid, data[i:]
        # 1. 收 login acknowledged (toServer 0x03)
        try:
            read_packet()
        except Exception:
            return
        # 2. 服务端发 select_known_packs 询问（0x0e）；764 无此阶段
        if off["cfg_known_packs"]:
            try:
                conn.sendall(_packet(0x0e, _varint(0)))
            except Exception:
                return
        # 3. 收 settings + (known_packs 响应) + finish
        n_cfg = 3 if off["cfg_known_packs"] else 2
        for _i in range(n_cfg):
            try:
                read_packet()
            except Exception:
                return
        # 4. 服务端回 finish → 进入 play
        conn.sendall(_packet(off["cfg_finish_cb"]))
        conn.sendall(_packet(0x2b, bytes.fromhex("00000000000000000000000000000001")))
        conn.sendall(_packet(off["play_ka"], (12345).to_bytes(8, "big")))
        # 5. 收聊天消息
        deadline = time.time() + 5
        conn.settimeout(0.5)
        while time.time() < deadline:
            try:
                pid, pl = read_packet()
                if pid == off["chat"]:
                    ulen, o = 0, 0
                    for _k in range(5):
                        b = pl[o]; ulen |= (b & 0x7F) << (7 * _k); o += 1
                        if not (b & 0x80):
                            break
                    msg = pl[o:o + ulen].decode("utf-8", "replace")
                    self.chat_messages.append(msg)
                    self.received.append(("chat", msg))
                elif pid == 0x04:  # chat_command（如 /login），忽略继续等 chat
                    self.received.append(("command", pl[:40]))
                else:
                    break
            except socket.timeout:
                continue  # 等待期间超时继续等，不退出
            except Exception:
                break

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass
