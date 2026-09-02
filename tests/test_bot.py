# -*- coding: utf-8 -*-
"""bot 发消息端到端测试：mock 完整流程 → 真实收到聊天消息"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from tests.mock_server import MockServer  # noqa: E402
from core.bot import MCBot  # noqa: E402

FAILED = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {detail}")
    if not cond:
        FAILED.append(name)


def test_send_chat():
    print("== 完整登录 + 发消息（mock 收到验证）==")
    for proto, ver in [(767, "1.21.1"), (771, "1.21.6"), (764, "1.20.2")]:
        m = MockServer(proto=proto, version=ver, auth="cracked", full_login=True)
        try:
            bot = MCBot("127.0.0.1", m.port, proto, username="BotTest",
                        timeout=5)
            t0 = time.time()
            ok = bot.connect()
            check(f"proto {proto} 登录+配置成功", ok, f"耗时 {time.time()-t0:.1f}s")
            bot.send_chat("hello from v2 test")
            bot.keep_alive_loop(duration=2.0)
            bot.close()
            time.sleep(0.3)
            got = m.chat_messages
            check(f"proto {proto} mock 收到消息", "hello from v2 test" in got,
                  f"收到 {got}")
        except Exception as e:
            check(f"proto {proto} 流程", False, f"异常: {e}")
        finally:
            m.close()
        time.sleep(0.3)


if __name__ == "__main__":
    test_send_chat()
    if FAILED:
        print(f"\n❌ {len(FAILED)} 项失败: {FAILED}")
        sys.exit(1)
    print("\n✅ bot 发消息测试全部通过")
