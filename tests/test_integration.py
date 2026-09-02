# -*- coding: utf-8 -*-
"""集成测试：mock 服务器 + ScanEngine 扫描 + SQLite 入库 + 查询（同一进程内）"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from tests.mock_server import MockServer  # noqa: E402
from scanner.engine import ScanEngine  # noqa: E402
from storage import db  # noqa: E402

DB = os.path.join(ROOT, "itest.db")


def main():
    if os.path.exists(DB):
        os.remove(DB)
    db.init_db(DB)

    # 起 3 个不同认证 + 1 个旧版本
    mocks = [
        MockServer(proto=771, version="1.21.6", auth="cracked", motd="Cracked S", online=5, maxp=50),
        MockServer(proto=764, version="1.20.2", auth="online", motd="Online S"),
        MockServer(proto=774, version="1.21.11", auth="whitelist", motd="Whitelist S"),
        MockServer(proto=767, version="1.21.1", auth="reject", motd="Reject S"),
    ]
    targets = [(f"127.0.0.1", m.port) for m in mocks]
    time.sleep(0.5)

    engine = ScanEngine(db_path=DB, workers=4, timeout=3)
    engine.scan_targets(iter(targets))
    print(f"扫描统计: {engine.counters}")

    rows = db.query(DB, limit=20)
    print(f"入库 {len(rows)} 条:")
    by_auth = {}
    for r in rows:
        by_auth[r["auth"]] = by_auth.get(r["auth"], 0) + 1
        print(f"  {r['ip']}:{r['port']} [{r['auth']}] {r['version']} {r['motd']}")
    print(f"统计: {db.stats(DB)}")

    # 验证
    ok = True
    expect = {"cracked": 1, "online": 1, "whitelist": 1, "rejected": 1}
    for k, v in expect.items():
        got = by_auth.get(k, 0)
        if got != v:
            print(f"[FAIL] {k}: 期望 {v} 实际 {got}")
            ok = False
    # 版本字段
    vers = {r["version"] for r in rows}
    for v in ("1.21.6", "1.20.2", "1.21.11", "1.21.1"):
        if v not in vers:
            print(f"[FAIL] 缺版本 {v}")
            ok = False

    for m in mocks:
        m.close()
    if os.path.exists(DB):
        os.remove(DB)
    print("\n✅ 集成测试通过" if ok else "\n❌ 集成测试失败")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
