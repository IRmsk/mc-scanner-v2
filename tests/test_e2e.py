# -*- coding: utf-8 -*-
"""端到端测试：用独立 mock 服务器验证探测与协议表正确性。"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))

from tests.mock_server import MockServer  # noqa: E402
from core.probe import slp_probe, auth_probe  # noqa: E402
from core import packets  # noqa: E402

FAILED = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name} {detail}")
    if not cond:
        FAILED.append(name)


def test_slp():
    print("== SLP 探测 ==")
    m = MockServer(proto=771, version="1.21.6", motd="Hello MC")
    try:
        r = slp_probe("127.0.0.1", m.port, timeout=3)
        check("SLP up", r.get("state") == "up", str(r))
        check("SLP proto", r.get("proto") == 771, f"got {r.get('proto')}")
        check("SLP version", r.get("version") == "1.21.6", r.get("version"))
        check("SLP motd", r.get("motd") == "Hello MC", repr(r.get("motd")))
        check("SLP online", r.get("online") == 2, str(r.get("online")))
    finally:
        m.close()


def test_auth_modes():
    print("== 认证模式三态 ==")
    # cracked
    m = MockServer(proto=771, version="1.21.6", auth="cracked")
    try:
        r = auth_probe("127.0.0.1", m.port, 771, timeout=3)
        check("cracked 识别", r["state"] == "cracked", str(r))
        check("cracked 协议回退确认", r["detected_proto"] == 771, str(r))
    finally:
        m.close()
    time.sleep(0.2)
    # online
    m = MockServer(proto=771, version="1.21.6", auth="online")
    try:
        r = auth_probe("127.0.0.1", m.port, 771, timeout=3)
        check("online 识别", r["state"] == "online", str(r))
    finally:
        m.close()
    time.sleep(0.2)
    # whitelist
    m = MockServer(proto=771, version="1.21.6", auth="whitelist")
    try:
        r = auth_probe("127.0.0.1", m.port, 771, timeout=3)
        check("whitelist 识别", r["state"] == "whitelist", str(r))
    finally:
        m.close()
    time.sleep(0.2)
    # reject（不含 whitelist 关键词）
    m = MockServer(proto=771, version="1.21.6", auth="reject")
    try:
        r = auth_probe("127.0.0.1", m.port, 771, timeout=3)
        check("reject 识别", r["state"] == "rejected", str(r))
    finally:
        m.close()


def test_multiple_versions():
    print("== 多版本协议兼容（SLP 报告各版本协议号 → auth 正确回退）==")
    for proto, ver in [(764, "1.20.2"), (767, "1.21.1"), (771, "1.21.6"), (774, "1.21.11")]:
        m = MockServer(proto=proto, version=ver, auth="cracked")
        try:
            r = auth_probe("127.0.0.1", m.port, proto, timeout=3)
            check(f"proto {proto} ({ver}) cracked", r["state"] == "cracked",
                  f"detected={r.get('detected_proto')}")
        finally:
            m.close()
        time.sleep(0.2)


def test_packet_selfcheck():
    print("== 协议表自检（已知官方值）==")
    check("packet 自检", packets._selfcheck())


if __name__ == "__main__":
    t0 = time.time()
    test_packet_selfcheck()
    test_slp()
    test_auth_modes()
    test_multiple_versions()
    print(f"\n耗时 {time.time()-t0:.1f}s")
    if FAILED:
        print(f"\n❌ {len(FAILED)} 项失败: {FAILED}")
        sys.exit(1)
    print("\n✅ 全部测试通过")
