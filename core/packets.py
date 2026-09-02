# -*- coding: utf-8 -*-
"""从 packet_ids 提供按协议号的包 ID 查询（自动生成数据，勿手改）"""
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from packet_ids import PACKET_TABLES, VERSION_LABEL  # noqa: E402

# 最高支持协议号（超出回退到已知最新表）
MAX_PROTO = max(t["proto"] for t in PACKET_TABLES)
MIN_PROTO = min(t["proto"] for t in PACKET_TABLES)


def get_table(proto: int):
    """返回精确协议号对应的表；超出范围回退到最近档位"""
    for t in PACKET_TABLES:
        if t["proto"] == proto:
            return t
    # 未收录：向上找最近的大于 proto 的表（新版本通常向后兼容登录协议）
    candidates = [t for t in PACKET_TABLES if t["proto"] > proto]
    if candidates:
        return min(candidates, key=lambda t: t["proto"])
    return PACKET_TABLES[-1]


def resolve_proto(proto: int) -> int:
    """把任意协议号解析到已收录档位"""
    return get_table(proto)["proto"]


def label_of(proto: int) -> str:
    return VERSION_LABEL.get(proto, f"proto {proto}")


def supported_protos():
    return [t["proto"] for t in PACKET_TABLES]


def _selfcheck():
    """自检：与已知官方正确值比对（防止生成脚本改动破坏）"""
    checks = [
        (764, "play", "sb_chat", 0x05), (765, "play", "sb_keep_alive", 0x15),
        (766, "play", "sb_chat", 0x06), (771, "play", "sb_chat", 0x08),
        (774, "play", "sb_chat", 0x08), (771, "play", "cb_disconnect", 0x1C),
        (768, "play", "sb_chat_command", 0x05), (773, "play", "sb_chat_command", 0x06),
        (770, "play", "cb_keep_alive", 0x26), (773, "play", "cb_keep_alive", 0x2B),
    ]
    ok = True
    for proto, stage, key, expect in checks:
        t = get_table(proto)
        actual = t[stage].get(key)
        if actual != expect:
            ok = False
            print(f"[FAIL] proto {proto} {stage}.{key} = {actual:#x}, 期望 {expect:#x}")
    return ok


if __name__ == "__main__":
    print(f"支持 {MIN_PROTO}-{MAX_PROTO}，共 {len(PACKET_TABLES)} 档")
    print("自检:", "通过" if _selfcheck() else "失败")
