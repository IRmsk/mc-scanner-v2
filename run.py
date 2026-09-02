#!/usr/bin/env python3
# 一键启动 Web 面板
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from web.app import run
port = int(sys.argv[1]) if len(sys.argv)>1 else 8080
run("servers.db", port=port)
