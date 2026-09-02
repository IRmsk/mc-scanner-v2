# -*- coding: utf-8 -*-
"""
masscan 端口发现封装。
改编自 mdberkey/minecraft-server-scanner (GPL-3.0) 的 scan.py，
扩展了多目标、可配置速率/端口/输出。

NOTICE: 本文件基于 GPL-3.0 项目 https://github.com/mdberkey/minecraft-server-scanner
        scan.py 改编，保留 GPL-3.0 许可。
"""
import os
import subprocess
import sys
from datetime import datetime


def get_config():
    return {
        'masscan_path': os.environ.get('MASSCAN_PATH', 'masscan'),
        'exclude_file': os.environ.get('EXCLUDE_FILE', 'exclude.conf'),
        'scan_output': os.environ.get('SCAN_OUTPUT', 'scan_results.ndjson'),
        'scan_rate': os.environ.get('SCAN_RATE', '1000'),
        'scan_port': os.environ.get('SCAN_PORT', '25565'),
        'source_port': os.environ.get('SOURCE_PORT', '61000'),
        'targets': os.environ.get('TARGETS', '0.0.0.0/0'),
    }


def build_cmd(config):
    cmd = [
        config['masscan_path'],
        '-p' + config['scan_port'],
        '--source-port', config['source_port'],
        '--rate', config['scan_rate'],
    ]
    if os.path.exists(config['exclude_file']):
        cmd += ['--excludefile', config['exclude_file']]
    cmd += ['--banners', '-oD', config['scan_output']]
    cmd += [config['targets']]
    return cmd


def run_scan(config=None, progress_cb=None):
    config = config or get_config()
    cmd = build_cmd(config)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] masscan: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] masscan 未安装或不在 PATH，请安装: sudo apt install masscan")
        return False

    if result.returncode != 0:
        print(f"[!] masscan 错误: {result.stderr[-500:]}")
        return False

    if progress_cb:
        progress_cb(config['scan_output'])
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 扫描完成 → {config['scan_output']}")
    return True


def main():
    ok = run_scan()
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
