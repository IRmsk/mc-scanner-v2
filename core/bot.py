# -*- coding: utf-8 -*-
"""完整登录 bot：login → configuration → play → 发聊天消息。
协议数据全部来自 packet_ids 自动生成表；配置阶段按各版本 settings/known_packs 差异兼容。
"""
import time
import uuid as uuid_mod

from .buffer import (write_varint, read_varint, write_string, write_uuid,
                     offline_uuid, read_string_from_stream, read_varint_from_stream)
from .conn import (MCConnection, PROTO_STATE_HANDSHAKE, PROTO_STATE_LOGIN,
                   PROTO_STATE_CONFIGURATION, PROTO_STATE_PLAY)
from . import packets


class MCBot:
    def __init__(self, host, port, proto, username="ScannerTest", timeout=6.0):
        self.host = host
        self.port = port
        self.proto = proto
        self.username = username
        self.timeout = timeout
        self.conn = None
        self.tab = packets.get_table(proto)
        self.state = None
        self.messages = []
        self._exit = False

    # ---- 登录阶段 ----
    def connect(self):
        conn = MCConnection(self.host, self.port, self.timeout)
        conn.handshake(self.proto, PROTO_STATE_LOGIN)
        tab = self.tab
        pid = tab["login_start"]
        payload = write_string(self.username)
        if self.proto >= 764:
            payload += write_uuid(offline_uuid(self.username))
        conn.send_packet(pid, payload)
        self.conn = conn

        # 登录响应循环
        while True:
            resp_id, resp_payload = conn.recv_packet()
            if resp_id == tab["login_compress"]:
                threshold, _ = read_varint(resp_payload, 0)
                conn.set_compression(threshold)
                continue
            if resp_id == tab["login_success"]:
                break
            if resp_id == tab["login_disconnect"]:
                reason = read_string_from_stream(_BytesStream(resp_payload)) if False else resp_payload
                raise ConnectionError(f"登录被拒绝: {reason[:100]}")
            if resp_id == tab["login_encryption_begin"]:
                raise ConnectionError("服务器要求正版验证（encryption）")

        # 回 login acknowledged → 进入 configuration
        conn.send_packet(tab["login_acknowledged"], b"")
        conn.state = PROTO_STATE_CONFIGURATION
        self.state = "configuration"
        self._configuration()
        return True

    def _configuration(self):
        """配置阶段（响应式流程，兼容 vanilla / Paper / Spigot）：
        发 settings → 收到 select_known_packs 询问时回空列表 → 发 finish → 等服务端确认"""
        conn = self.conn
        tab = self.tab
        cfg = tab["config"]

        deadline = time.time() + self.timeout * 2
        self._send_settings()
        sent_known = False   # 是否已响应 known_packs 询问
        sent_finish = False
        first = time.time()
        conn.sock.settimeout(0.5)  # 配置阶段短超时，让兜底逻辑能及时触发
        while time.time() < deadline:
            # 收到 known_packs 询问后可发 finish；若 1.5s 内服务端一直未询问也未 finish，主动发 finish 兜底
            if not sent_finish:
                should = sent_known or (time.time() - first > 1.5)
                if should:
                    if cfg.get("sb_known_packs") is not None and not sent_known:
                        conn.send_packet(cfg["sb_known_packs"], write_varint(0))
                        sent_known = True
                    if cfg.get("sb_finish") is not None:
                        conn.send_packet(cfg["sb_finish"], b"")
                        sent_finish = True
            try:
                resp_id, resp_payload = conn.recv_packet()
            except Exception:
                continue  # 超时 → 回到循环检查兜底
            if resp_id == cfg["cb_finish"]:
                conn.state = PROTO_STATE_PLAY
                self.state = "play"
                conn.sock.settimeout(self.timeout)
                return
            elif resp_id == cfg.get("cb_disconnect"):
                raise ConnectionError("配置阶段被断开")
            elif resp_id == cfg.get("cb_keep_alive"):
                conn.send_packet(cfg["sb_keep_alive"], resp_payload[:8])
            elif resp_id == cfg.get("cb_ping"):
                conn.send_packet(cfg["sb_pong"], resp_payload[:4])
            elif cfg.get("cb_known_packs") is not None and resp_id == cfg["cb_known_packs"]:
                # 服务端询问已知包 → 回空列表（下次循环发 finish）
                if cfg.get("sb_known_packs") is not None:
                    conn.send_packet(cfg["sb_known_packs"], write_varint(0))
                    sent_known = True
            # 其余配置包（registry_data/feature_flags/tags/custom_payload 等）忽略

    def _send_settings(self):
        conn = self.conn
        cfg = self.tab["config"]
        # settings (client_information)：各版本字段一致（1.21.1 无 particleStatus）
        payload = (write_string("en_US")
                   + bytes([8])            # viewDistance
                   + write_varint(0)       # chatMode
                   + b"\x01"               # chatColors true
                   + bytes([0x7f])         # skinParts
                   + write_varint(1)       # mainHand right
                   + b"\x00"               # enableTextFiltering false
                   + b"\x01")              # enableServerListing true
        conn.send_packet(cfg["sb_client_info"], payload)

    # ---- play 阶段 ----
    def send_chat(self, message):
        """发送聊天消息（1.20.2+ 格式）"""
        if self.state != "play":
            raise RuntimeError("尚未进入 play 阶段")
        p = self.tab["play"]
        payload = (write_string(message)
                   + int(time.time() * 1000).to_bytes(8, "big")   # timestamp i64
                   + (0).to_bytes(8, "big")                       # salt i64
                   + write_varint(0)                              # signature 空
                   + write_varint(0)                              # offset/msgCount
                   + write_varint(0))                             # acknowledged 空
        self.conn.send_packet(p["sb_chat"], payload)
        self.messages.append(message)

    def send_command(self, command):
        """发送命令（不含前导 /），如 'login 12345' / 'register 12345 12345'"""
        if self.state != "play":
            raise RuntimeError("尚未进入 play 阶段")
        p = self.tab["play"]
        self.conn.send_packet(p["sb_chat_command"], write_string(command))
        self.messages.append("/" + command)

    def authme_login(self, password, register=False):
        """AuthMe 登录：已注册用 /login，未注册用 /register 密码 密码"""
        if register:
            self.send_command(f"register {password} {password}")
        else:
            self.send_command(f"login {password}")
        time.sleep(2.5)  # 等 AuthMe 处理登录

    def keep_alive_loop(self, duration=3.0):
        """保持连接，处理 keep_alive / ping，直到时长到或断开"""
        conn = self.conn
        tab = self.tab
        deadline = time.time() + duration
        conn.sock.settimeout(0.5)
        while time.time() < deadline:
            try:
                resp_id, resp_payload = conn.recv_packet()
            except Exception:
                continue  # 超时
            p = tab["play"]
            if resp_id == p["cb_keep_alive"]:
                conn.send_packet(p["sb_keep_alive"], resp_payload[:8])
            elif resp_id == p["cb_ping"]:
                conn.send_packet(p["sb_pong"], resp_payload[:4])
            elif resp_id == p.get("cb_disconnect"):
                break

    def close(self):
        if self.conn:
            self.conn.close()


class _BytesStream:
    """把 bytes 包装成带 read 的对象（复用流读取函数）"""
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, n=-1):
        if n < 0:
            n = len(self.data) - self.pos
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk
