#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MC Scanner V2 - 综合 MC 服务器扫描器
借鉴 19 个同类开源项目构建，功能整合超越单项目。

用法:
  python3 cli.py scan 1.2.3.4,5.6.7.0/24          # 直接扫描目标（SLP + 认证检测）
  python3 cli.py scan --auth-only 目标              # 只做认证检测
  python3 cli.py masscan --targets 0.0.0.0/0       # masscan 全网端口发现（需安装 masscan）
  python3 cli.py import scan_results.ndjson         # 导入 masscan 结果
  python3 cli.py web --port 8080                    # 启动 Web 面板
  python3 cli.py query --auth cracked               # 查询数据库
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def cmd_scan(args):
    from scanner.targets import parse_targets
    from scanner.exclude import Excluder
    from scanner.engine import ScanEngine
    from storage import db
    db.init_db(args.db)
    ex = Excluder(args.exclude)
    targets = ex.filter_targets(parse_targets(args.targets))
    engine = ScanEngine(db_path=args.db, workers=args.workers, timeout=args.timeout,
                        auth_check=args.auth, rate_limit=args.rate)
    print(f"[*] 开始扫描（workers={args.workers}, auth={args.auth}, 限速={args.rate}/s）")
    engine.scan_targets(targets)
    print(f"[*] 完成。统计: {engine.counters}")
    if args.web:
        from web.app import run
        run(args.db, port=args.web)


def cmd_masscan(args):
    from scanner.scan import get_config, run_scan
    config = get_config()
    if args.targets:
        config['targets'] = args.targets
    if args.rate:
        config['scan_rate'] = str(args.rate)
    if args.port:
        config['scan_port'] = str(args.port)
    if args.exclude:
        config['exclude_file'] = args.exclude
    config['scan_output'] = args.output
    ok = run_scan(config)
    if ok and args.auto_import:
        cmd_import(argparse.Namespace(
            db=args.db, ndjson=args.output, auth=args.auth, workers=args.workers,
            timeout=args.timeout, rate=args.rate))
    return 0 if ok else 1


def cmd_import(args):
    from scanner.engine import ScanEngine
    engine = ScanEngine(db_path=args.db, workers=args.workers, timeout=args.timeout,
                        auth_check=args.auth, rate_limit=args.rate)
    engine.import_masscan(args.ndjson, then_auth=args.auth)
    print(f"[*] 导入完成。统计: {engine.counters}")


def cmd_web(args):
    from web.app import run
    run(args.db, port=args.port)


def cmd_bot(args):
    """完整登录 + AuthMe 登录 + 发消息（需目标授权）"""
    from core.bot import MCBot
    host, port = args.target.rsplit(":", 1)
    bot = MCBot(host, int(port), args.proto, username=args.username, timeout=args.timeout)
    try:
        bot.connect()
        print(f"[+] 登录成功进入 play (proto {args.proto}, 玩家 {args.username})")
        if args.authme:
            print(f"[+] AuthMe 检测到，执行 {'/register' if args.register else '/login'}...")
            bot.authme_login(args.authme, register=args.register)
        if args.message:
            bot.send_chat(args.message)
            print(f"[+] 已发送: {args.message}")
        bot.keep_alive_loop(args.hold)
        print("[+] 保持连接结束，未被踢")
    finally:
        bot.close()


def cmd_query(args):
    from storage import db
    rows = db.query(args.db, auth=args.auth, modded=args.modded,
                    search=args.search, limit=args.limit)
    print(f"{len(rows)} 条结果:")
    for r in rows:
        print(f"  {r['ip']}:{r['port']} [{r['auth']}] {r['version']} "
              f"在线 {r['players_online']}/{r['players_max']} · {r['motd'][:40]}")


def main():
    p = argparse.ArgumentParser(description="MC Scanner V2")
    p.add_argument("--db", default="servers.db")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="直接扫描目标")
    s.add_argument("targets")
    s.add_argument("--workers", type=int, default=32)
    s.add_argument("--timeout", type=float, default=4.0)
    s.add_argument("--no-auth", dest="auth", action="store_false", default=True,
                   help="跳过认证模式检测")
    s.add_argument("--rate", type=int, default=0, help="限速(次/秒)")
    s.add_argument("--exclude", default="exclude.conf")
    s.add_argument("--web", type=int, default=0, help="扫描后启动 Web 面板端口")
    s.set_defaults(func=cmd_scan)

    m = sub.add_parser("masscan", help="masscan 全网端口发现")
    m.add_argument("--targets", default=None)
    m.add_argument("--rate", type=int, default=0)
    m.add_argument("--port", default="25565")
    m.add_argument("--output", default="scan_results.ndjson")
    m.add_argument("--exclude", default="exclude.conf")
    m.add_argument("--auto-import", action="store_true", help="扫描后自动导入+认证检测")
    m.add_argument("--workers", type=int, default=32)
    m.add_argument("--timeout", type=float, default=4.0)
    m.add_argument("--no-auth", dest="auth", action="store_false", default=True)
    m.add_argument("--rate2", dest="rate", type=int, default=0)
    m.set_defaults(func=cmd_masscan)

    i = sub.add_parser("import", help="导入 masscan NDJSON 结果")
    i.add_argument("ndjson")
    i.add_argument("--workers", type=int, default=32)
    i.add_argument("--timeout", type=float, default=4.0)
    i.add_argument("--no-auth", dest="auth", action="store_false", default=True)
    i.add_argument("--rate", type=int, default=0)
    i.set_defaults(func=cmd_import)

    w = sub.add_parser("web", help="启动 Web 面板")
    w.add_argument("--port", type=int, default=8080)
    w.set_defaults(func=cmd_web)

    b = sub.add_parser("bot", help="完整登录 + AuthMe 登录 + 发消息（仅限授权目标）")
    b.add_argument("target", help="host:port")
    b.add_argument("--proto", type=int, default=767, help="协议号")
    b.add_argument("--username", default="him")
    b.add_argument("--message", default=None, help="要发的聊天消息")
    b.add_argument("--authme", default=None, metavar="PASS", help="AuthMe 密码（触发 /login）")
    b.add_argument("--register", action="store_true", help="未注册账号用 /register（需 --authme）")
    b.add_argument("--timeout", type=float, default=8.0)
    b.add_argument("--hold", type=float, default=4.0, help="保持连接秒数")
    b.set_defaults(func=cmd_bot)

    q = sub.add_parser("query", help="查询数据库")
    q.add_argument("--auth", default=None)
    q.add_argument("--modded", type=int, default=None)
    q.add_argument("--search", default=None)
    q.add_argument("--limit", type=int, default=50)
    q.set_defaults(func=cmd_query)

    args = p.parse_args()
    if not getattr(args, "func", None):
        p.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
