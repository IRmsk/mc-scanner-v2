# -*- coding: utf-8 -*-
"""目标解析：IP/网段/文件，使用惰性生成器避免大网段 OOM（借鉴 matscan/mdberkey 思路）"""
import ipaddress
import os
import re


def parse_targets(spec):
    """把目标规格解析为惰性生成器。
    支持: 单个IP / CIDR网段 / 逗号分隔 / 文件路径(每行一个目标)
    返回 (ip_str, port) 生成器；port 默认 25565 或 target:port 形式。
    """
    specs = spec.split(',') if ',' in spec else [spec]
    for s in specs:
        s = s.strip()
        if not s:
            continue
        if os.path.isfile(s):
            with open(s, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        yield from _parse_one(line)
        else:
            yield from _parse_one(s)


def _parse_one(text):
    port = 25565
    if '/' in text and not text.startswith(('http', 'https')):
        m = re.match(r'^([^:]+):(\d+)$', text)
        if m:  # 如 1.2.3.4:25566
            text, port = m.group(1), int(m.group(2))
    m = re.match(r'^(.+?):(\d+)$', text)
    if m and m.group(1).count(':') == 0:  # IPv4:port
        text, port = m.group(1), int(m.group(2))
    try:
        if '/' in text:
            net = ipaddress.ip_network(text, strict=False)
            if net.num_addresses <= 1:
                yield str(net.network_address), port
                return
            # 大网段惰性遍历
            for ip in net.hosts():
                yield str(ip), port
        else:
            ipaddress.ip_address(text)  # 校验
            yield text, port
    except ValueError:
        yield text, port  # 域名（如 mc.hypixel.net）交给 socket 解析
