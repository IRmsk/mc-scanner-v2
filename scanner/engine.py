# -*- coding: utf-8 -*-
"""综合扫描引擎：SLP 元数据 + 认证模式检测 + 存储（借鉴 matscan 的两阶段分离架构）"""
import concurrent.futures
import json
import threading
import time

from core import packets
from core.probe import slp_probe, auth_probe
from storage import db
from scanner.banner import extract_records, parse_banner


class ScanEngine:
    def __init__(self, db_path="servers.db", workers=32, timeout=4.0,
                 auth_check=True, rate_limit=0):
        """
        rate_limit: 每秒最多探测次数（0 = 不限速），用于合规限速
        auth_check: 是否做认证模式检测（登录试探，较慢且有痕迹）
        """
        self.db_path = db_path
        self.workers = workers
        self.timeout = timeout
        self.auth_check = auth_check
        self.rate_limit = rate_limit
        self._lock = threading.Lock()
        self._last_probe = 0.0
        self.counters = {"up": 0, "cracked": 0, "online": 0, "whitelist": 0,
                         "rejected": 0, "offline": 0, "error": 0}
        self.results = []

    # ---- 限速 ----
    def _throttle(self):
        if self.rate_limit <= 0:
            return
        with self._lock:
            now = time.time()
            wait = (1.0 / self.rate_limit) - (now - self._last_probe)
            if wait > 0:
                time.sleep(wait)
            self._last_probe = time.time()

    # ---- 单目标探测 ----
    def probe_one(self, ip, port):
        self._throttle()
        result = {"ip": ip, "port": port, "auth": "error", "error": ""}
        try:
            up = slp_probe(ip, port, self.timeout)
            if up.get("state") == "up":
                result.update({k: up.get(k) for k in
                               ("version", "proto", "motd", "ping_ms")})
                result["players_online"] = up.get("online", 0)
                result["players_max"] = up.get("max", 0)
                result["is_modded"] = 1 if _looks_modded(up.get("version", "")) else 0
                result["state"] = "up"
                self._bump("up")
            else:
                result["state"] = "offline"
                result["error"] = up.get("error", "")
                self._bump("offline")
                return result

            if self.auth_check:
                proto = result.get("proto") or 0
                auth = auth_probe(ip, port, proto, timeout=self.timeout)
                result["auth"] = auth["state"]
                result["auth_detail"] = auth.get("detail", "")
                if auth.get("detected_proto"):
                    result["proto"] = auth["detected_proto"]
                self._bump(result["auth"])
            else:
                result["auth"] = "unknown"
        except Exception as e:
            result["state"] = "error"
            result["error"] = str(e)
            self._bump("error")
        return result

    def _bump(self, key):
        with self._lock:
            if key in self.counters:
                self.counters[key] += 1

    # ---- 批处理 ----
    def scan_targets(self, targets, save_every=50):
        """targets: (ip, port) 惰性生成器"""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(self.probe_one, ip, port): (ip, port)
                       for ip, port in targets}
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                try:
                    r = fut.result()
                except Exception as e:
                    ip, port = futures[fut]
                    r = {"ip": ip, "port": port, "state": "error", "error": str(e)}
                results.append(r)
                done += 1
                if done % save_every == 0:
                    db.upsert_many(self.db_path, results[-save_every:])
                    self._progress(done)
        if results:
            db.upsert_many(self.db_path, results)
        return results

    def _progress(self, done):
        c = dict(self.counters)
        print(f"[{done:>6}] up={c['up']} cracked={c['cracked']} "
              f"online={c['online']} whitelist={c['whitelist']} offline={c['offline']}")

    # ---- 从 masscan 结果入库（banner 阶段） ----
    def import_masscan(self, ndjson_path, then_auth=True):
        """先导入 masscan banner（快），再对在线的做认证检测（慢）"""
        db.init_db(self.db_path)
        print(f"[*] 导入 masscan banner: {ndjson_path}")
        pending = []
        for ip, port, banner in extract_records(ndjson_path):
            p = parse_banner(banner)
            if not p:
                continue
            p["ip"], p["port"] = ip, port
            p["auth"] = "unknown"
            pending.append(p)
            if len(pending) >= 500:
                db.upsert_many(self.db_path, pending)
                pending = []
        if pending:
            db.upsert_many(self.db_path, pending)
        print(f"[*] banner 导入完成，共 {len(pending) and '已分批写入' or '0'} 条处理")

        if then_auth:
            targets = [(r["ip"], r["port"]) for r in db.query(self.db_path, limit=100000)]
            print(f"[*] 对 {len(targets)} 个已发现服务器做认证检测...")
            self.scan_targets(iter(targets))


def _looks_modded(version):
    v = version.lower()
    return any(kw in v for kw in ("forge", "fabric", "mod", "paper", "spigot",
                                  "bukkit", "purpur", "fml"))
