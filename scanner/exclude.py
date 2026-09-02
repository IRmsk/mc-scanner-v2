# -*- coding: utf-8 -*-
"""排除列表：过滤云厂商/公开服务商 IP 段（借鉴 matscan 的 exclude.conf 与 mdberkey 的 masscan excludefile）"""
import ipaddress
import os


DEFAULT_EXCLUDES = [
    # 常用云厂商/托管商保留段（可按需扩充）
    "10.0.0.0/8",      # 私有
    "172.16.0.0/12",   # 私有
    "192.168.0.0/16",  # 私有
    "169.254.0.0/16",  # 链路本地
    "224.0.0.0/4",     # 组播
    "0.0.0.0/8",
    "100.64.0.0/10",   # CGNAT
]


class Excluder:
    def __init__(self, exclude_file=None, extra=None):
        self.nets = [ipaddress.ip_network(x) for x in DEFAULT_EXCLUDES]
        if extra:
            for x in extra:
                self._add(x)
        if exclude_file and os.path.exists(exclude_file):
            with open(exclude_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip().split()[0] if line.strip() else ''
                    if line and not line.startswith('#'):
                        self._add(line)

    def _add(self, spec):
        try:
            self.nets.append(ipaddress.ip_network(spec, strict=False))
        except ValueError:
            pass

    def is_excluded(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in net for net in self.nets)

    def filter_targets(self, targets):
        """包装目标生成器，过滤掉排除网段"""
        for ip, port in targets:
            if not self.is_excluded(ip):
                yield ip, port
