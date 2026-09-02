# -*- coding: utf-8 -*-
"""
SQLite 存储层。
改编自 mdberkey/minecraft-server-scanner (GPL-3.0) 的 import_db.py，
去 orjson 依赖、扩展认证模式与协议字段。

NOTICE: 基于 GPL-3.0 项目 https://github.com/mdberkey/minecraft-server-scanner
        import_db.py 改编，保留 GPL-3.0 许可。
"""
import os
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    ip TEXT,
    port INTEGER,
    version TEXT,
    proto INTEGER,
    motd TEXT,
    is_modded INTEGER,
    players_online INTEGER,
    players_max INTEGER,
    favicon TEXT,
    auth TEXT,
    ping_ms INTEGER,
    json TEXT,
    last_updated TEXT,
    PRIMARY KEY (ip, port)
)
"""

UPSERT_SQL = """
    INSERT INTO servers (ip, port, version, proto, motd, is_modded, players_online,
                         players_max, favicon, auth, ping_ms, json, last_updated)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip, port) DO UPDATE SET
        version=excluded.version, proto=excluded.proto, motd=excluded.motd,
        is_modded=excluded.is_modded, players_online=excluded.players_online,
        players_max=excluded.players_max, favicon=excluded.favicon,
        auth=excluded.auth, ping_ms=excluded.ping_ms,
        json=excluded.json, last_updated=excluded.last_updated
"""


def get_conn(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


def init_db(db_path):
    conn = get_conn(db_path)
    conn.execute(SCHEMA)
    conn.commit()
    conn.close()


def upsert_server(db_path, rec):
    conn = get_conn(db_path)
    conn.execute(UPSERT_SQL, (
        rec['ip'], rec['port'], rec.get('version'), rec.get('proto'),
        rec.get('motd'), rec.get('is_modded', 0), rec.get('players_online', 0),
        rec.get('players_max', 0), rec.get('favicon'), rec.get('auth', 'unknown'),
        rec.get('ping_ms'), rec.get('json'),
        datetime.now(timezone.utc).isoformat(),
    ))
    conn.commit()
    conn.close()


def upsert_many(db_path, records):
    if not records:
        return 0
    conn = get_conn(db_path)
    rows = [(
        r['ip'], r['port'], r.get('version'), r.get('proto'), r.get('motd'),
        r.get('is_modded', 0), r.get('players_online', 0), r.get('players_max', 0),
        r.get('favicon'), r.get('auth', 'unknown'), r.get('ping_ms'), r.get('json'),
        datetime.now(timezone.utc).isoformat(),
    ) for r in records]
    conn.executemany(UPSERT_SQL, rows)
    conn.commit()
    conn.close()
    return len(rows)


def query(db_path, auth=None, modded=None, search=None, limit=200, offset=0):
    conn = get_conn(db_path)
    cols = ["ip", "port", "version", "proto", "motd", "is_modded",
            "players_online", "players_max", "auth", "ping_ms", "last_updated"]
    sql = "SELECT " + ", ".join(cols) + " FROM servers"
    conds, args = [], []
    if auth:
        conds.append("auth = ?")
        args.append(auth)
    if modded is not None:
        conds.append("is_modded = ?")
        args.append(1 if modded else 0)
    if search:
        conds.append("(motd LIKE ? OR version LIKE ? OR ip LIKE ?)")
        args += [f"%{search}%"] * 3
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY last_updated DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return [dict(zip(cols, r)) for r in rows]


def stats(db_path):
    conn = get_conn(db_path)
    total = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
    by_auth = {r[0]: r[1] for r in conn.execute(
        "SELECT auth, COUNT(*) FROM servers GROUP BY auth")}
    online_servers = conn.execute("SELECT COUNT(*) FROM servers WHERE players_online > 0").fetchone()[0]
    conn.close()
    return {"total": total, "by_auth": by_auth, "online_servers": online_servers}
