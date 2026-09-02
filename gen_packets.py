#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 PrismarineJS/minecraft-data 的 protocol.json 自动生成协议包 ID 表。
这是本项目协议正确性的根基：数据直接来自官方，杜绝手抄错误。

用法: python3 gen_packets.py
输出: mcdata/../packet_ids.py
"""
import json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
MCDATA = os.path.join(HERE, "mcdata")

# 版本 -> 协议号（官方映射）
VERSION_PROTOCOL = {
    "1.20.2": 764, "1.20.3": 765, "1.20.5": 766, "1.21.1": 767,
    "1.21.3": 768, "1.21.4": 769, "1.21.5": 770, "1.21.6": 771,
    "1.21.8": 772, "1.21.9": 773, "1.21.11": 774,
}
PROTOCOL_LABEL = {
    764: "1.20.2", 765: "1.20.3-1.20.4", 766: "1.20.5-1.20.6",
    767: "1.21-1.21.1", 768: "1.21.2-1.21.3", 769: "1.21.4",
    770: "1.21.5", 771: "1.21.6", 772: "1.21.7-1.21.8", 773: "1.21.9",
    774: "1.21.10-1.21.11",
}


def packet_map(d, stage, side):
    """从 packet 类型提取 {packet名: 包ID}"""
    m = d[stage][side]["types"]["packet"]
    for f in m[1]:
        if f.get("name") == "name":
            return {v: int(k, 16) for k, v in f["type"][1]["mappings"].items()}
    return {}


def get_protocol_from_json(d):
    """尝试从 json 里取协议号（可能没有）"""
    if "protocolVersion" in d:
        return d["protocolVersion"]
    return None


def build_table(proto, d):
    """为一个协议号提取全部关键包 ID"""
    t = {"proto": proto, "label": PROTOCOL_LABEL.get(proto, str(proto))}
    login_sb = packet_map(d, "login", "toServer")
    login_cb = packet_map(d, "login", "toClient")
    cfg_sb = packet_map(d, "configuration", "toServer")
    cfg_cb = packet_map(d, "configuration", "toClient")
    play_sb = packet_map(d, "play", "toServer")
    play_cb = packet_map(d, "play", "toClient")

    # login
    t["login_start"] = login_sb.get("login_start")
    t["login_acknowledged"] = login_sb.get("login_acknowledged", 0x03)
    t["login_success"] = login_cb.get("success")
    t["login_compress"] = login_cb.get("compress")
    t["login_encryption_begin"] = login_cb.get("encryption_begin")
    t["login_disconnect"] = login_cb.get("disconnect")

    # configuration
    t["config"] = {
        "sb_client_info": cfg_sb.get("client_information") or cfg_sb.get("settings"),
        "sb_plugin": cfg_sb.get("plugin_message") or cfg_sb.get("custom_payload"),
        "sb_finish": cfg_sb.get("finish_configuration"),
        "sb_keep_alive": cfg_sb.get("keep_alive"),
        "sb_pong": cfg_sb.get("pong"),
        "sb_known_packs": cfg_sb.get("known_packs") or cfg_sb.get("select_known_packs"),
        "sb_resource_pack": cfg_sb.get("resource_pack_response") or cfg_sb.get("resource_pack_receive"),
        "cb_finish": cfg_cb.get("finish_configuration"),
        "cb_keep_alive": cfg_cb.get("keep_alive"),
        "cb_ping": cfg_cb.get("ping"),
        "cb_registry_data": cfg_cb.get("registry_data"),
        "cb_disconnect": cfg_cb.get("kick_disconnect"),
        "cb_known_packs": cfg_cb.get("known_packs") or cfg_cb.get("select_known_packs"),
        "cb_resource_pack": cfg_cb.get("resource_pack_send") or cfg_cb.get("add_resource_pack"),
    }

    # play
    t["play"] = {
        "sb_chat": play_sb.get("chat_message"),
        "sb_chat_command": play_sb.get("chat_command"),
        "sb_keep_alive": play_sb.get("keep_alive"),
        "sb_pong": play_sb.get("pong"),
        "sb_confirm_teleport": play_sb.get("confirm_teleport"),
        "sb_client_information": play_sb.get("client_information"),
        "cb_keep_alive": play_cb.get("keep_alive"),
        "cb_ping": play_cb.get("ping"),
        "cb_login": play_cb.get("login"),
        "cb_disconnect": play_cb.get("kick_disconnect"),
        "cb_player_chat": play_cb.get("player_chat"),
        "cb_system_chat": play_cb.get("system_chat_message"),
    }
    return t


def main():
    tables = []
    for ver, proto in sorted(VERSION_PROTOCOL.items(), key=lambda x: x[1]):
        path = os.path.join(MCDATA, f"proto_{ver}.json")
        if not os.path.exists(path):
            print(f"[skip] {ver} 无数据")
            continue
        d = json.load(open(path))
        tables.append(build_table(proto, d))
        print(f"[ok] {ver} (proto {proto})")

    # 生成 Python 模块
    lines = []
    lines.append('# -*- coding: utf-8 -*-')
    lines.append('# 本文件由 gen_packets.py 从 PrismarineJS/minecraft-data 自动生成，请勿手改。')
    lines.append('# 生成时间: 自动')
    lines.append('')
    lines.append('PACKET_TABLES = [')
    for t in tables:
        lines.append(repr(t) + ',')
    lines.append(']')
    lines.append('')
    lines.append('VERSION_LABEL = {')
    for proto, label in sorted(PROTOCOL_LABEL.items()):
        lines.append(f'    {proto}: "{label}",')
    lines.append('}')
    lines.append('')
    out = "\n".join(lines)
    with open(os.path.join(HERE, "packet_ids.py"), "w", encoding="utf-8") as f:
        f.write(out)
    print(f"\n生成完成: {os.path.join(HERE, 'packet_ids.py')} ({len(tables)} 个协议档位)")


if __name__ == "__main__":
    main()
