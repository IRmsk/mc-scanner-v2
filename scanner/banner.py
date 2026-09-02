# -*- coding: utf-8 -*-
"""
masscan banner 解析（SLP status JSON）。
改编自 mdberkey/minecraft-server-scanner (GPL-3.0) 的 import_db.py parse_banner，
去掉 orjson 依赖改为标准库 json，并增加协议号提取。

NOTICE: 基于 GPL-3.0 项目 https://github.com/mdberkey/minecraft-server-scanner
        import_db.py 改编，保留 GPL-3.0 许可。
"""
import json
import os


def parse_chat(chat_obj):
    """解析 MC 聊天组件 JSON → 纯文本 MOTD"""
    if isinstance(chat_obj, str):
        return chat_obj
    if isinstance(chat_obj, list):
        return "".join(parse_chat(item) for item in chat_obj)
    if not isinstance(chat_obj, dict):
        return str(chat_obj) if chat_obj is not None else ""
    text = str(chat_obj.get('text', '') or '')
    extra = chat_obj.get('extra')
    if isinstance(extra, list):
        for item in extra:
            text += parse_chat(item)
    return text


def parse_banner(banner_str):
    """解析一条 SLP status JSON → 结构化字段"""
    try:
        res = json.loads(banner_str)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(res, dict) or 'description' not in res:
        return None

    desc = res.get('description')
    if desc is None:
        return None

    motd = parse_chat(desc) if isinstance(desc, (dict, list)) else str(desc)

    ver = res.get('version', {}) or {}
    v_name = str(ver.get('name', 'Unknown'))
    proto = int(ver.get('protocol', 0) or 0)

    v_low = v_name.lower()
    is_modded = any(kw in v_low for kw in ('forge', 'fabric', 'mod', 'paper', 'spigot', 'bukkit', 'purpur'))
    if (res.get('modinfo') or {}).get('type') == 'FML':
        is_modded = True

    players = res.get('players', {}) or {}
    return {
        'motd': motd,
        'version': v_name,
        'proto': proto,
        'is_modded': 1 if is_modded else 0,
        'players_online': players.get('online', 0) or 0,
        'players_max': players.get('max', 0) or 0,
        'favicon': res.get('favicon'),
    }


def extract_records(log_path):
    """从 masscan NDJSON 输出中逐行提取 (ip, port, banner)"""
    if not os.path.exists(log_path):
        return
    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip().rstrip(',')
            if not line or line[0] in ('#', '[', ']', '{', '}'):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            # masscan --banners 输出格式
            data = record.get('data', {})
            banner = data.get('banner')
            ip = record.get('ip')
            if banner and ip:
                port = record.get('ports', [{}])[0].get('port', 25565) if record.get('ports') else 25565
                yield (ip, port, banner)
