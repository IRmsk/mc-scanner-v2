# MC Scanner V2

> ## ⚠️ 已停止维护
>
> 本项目（v2）已停止更新，功能已完全被 **[mc-scanner-v3](https://github.com/2584210631-star/mc-scanner-v3)** 取代。
>
> v3 支持正版 OAuth 登录、聊天签名、多机器人并发、AI 托管、分布式扫描、移动端适配等大量新功能，建议直接迁移到 v3。
>
> 本仓库仅作历史留存，不再接受 issue 和 PR。

综合 Minecraft 服务器扫描器——整合 19 个同类开源项目优点构建的"超越版"。

## 功能（对标各项目）

| 能力 | 本项目 | 来源/参考 |
|---|---|---|
| 协议包 ID 表**自动生成**（不手抄） | ✅ `gen_packets.py` | azalea (codegen) + PrismarineJS/minecraft-data |
| 全网端口发现（masscan） | ✅ `masscan` 子命令 | mdberkey / matscan |
| SLP 元数据采集（MOTD/版本/人数/延迟） | ✅ `slp_probe` | mdberkey / hoellwerth |
| 认证模式三态检测（正版/破解/白名单） | ✅ `auth_probe` | mcprobe / DilanBlue / MineScan |
| 协议多级回退（未知协议号自动试） | ✅ | DilanBlue checkWhitelistSmart |
| 白名单关键词识别 | ✅ | DilanBlue |
| 排除列表（过滤云厂商/私有段） | ✅ `exclude.conf` | matscan / mdberkey |
| SQLite 存储 + 去重更新 | ✅ | mdberkey import_db |
| Web 面板（搜索/过滤/分页/统计） | ✅ 零依赖 | mdberkey Flask / 主角 mc-scanner |
| 限速（合规） | ✅ `--rate` | DilanBlue README 建议 |
| 独立 mock 端到端测试 | ✅ | 主角 mc-scanner（吸取"假成功"教训） |

## 快速开始

```bash
# 1. 生成协议表（从官方 minecraft-data，需要网络，只需跑一次）
python3 gen_packets.py

# 2. 直接扫描一批目标（IP / CIDR / 域名 / 文件，逗号分隔）
python3 cli.py scan 1.2.3.4,5.6.7.0/24,my.server.com

# 3. 扫描结果进 Web 面板
python3 cli.py scan 1.2.3.4 --web 8080
# 打开 http://localhost:8080

# 4. masscan 全网扫描（需先安装 masscan: sudo apt install masscan）
python3 cli.py masscan --targets 0.0.0.0/0 --rate 1000 --auto-import

# 5. 查询数据库
python3 cli.py query --auth cracked
```

## CLI 全部命令

```
python3 cli.py scan   目标      # 直接扫描（SLP + 认证检测）
python3 cli.py masscan          # masscan 端口发现 → 可选自动导入
python3 cli.py import 文件.ndjson # 导入 masscan 结果
python3 cli.py web     --port 8080
python3 cli.py query   --auth cracked --search xxx
python3 cli.py bot    host:port --proto 767 --message "..."  # 完整登录并发消息（仅限授权目标！）
```

常用参数：`--workers N` 并发数、`--timeout S`、`--rate N/s` 限速、`--no-auth` 跳过登录探测、`--exclude 文件`、`--db 路径`。

## 测试

```bash
python3 tests/test_e2e.py          # 独立 mock 端到端（协议正确性 + 三态检测）
python3 tests/test_integration.py  # mock + 扫描 + 入库 + 查询
```

mock 服务器的包 ID 为官方手工核对常量，与实现**分离**，专防"自报成功但实际无效"类 bug。

## 法律与伦理（重要）

本工具会向目标服务器发起 TCP 连接、SLP 查询、**登录试探**，`bot` 命令还会**完整登录并发消息**（会留下机器人账号与聊天记录）。使用前请确保：
1. **只扫描自己拥有/已获授权**的服务器；
2. 遵守目标网络所在司法辖区的法律（未经授权扫描在多数地区违法）；
3. 控制扫描速率（建议 `--rate 500` 以下），避免骚扰；
4. 请勿用于攻击、骚扰或任何非法用途。

参考合规模板：DilanBlue/mc-scanner README。

## 许可与来源（NOTICE）

本项目整体为 **GPL-3.0**（因包含 GPL-3.0 来源代码）。所有借鉴来源及许可见 [NOTICE](NOTICE)。

- 直接改编（保留 GPL-3.0）：mdberkey/minecraft-server-scanner（scan.py / import_db.py）
- 思路参考（MIT）：matscan、azalea、DilanBlue/mc-scanner、PrismarineJS/minecraft-data
- 思路参考（未标许可，仅借鉴思路未抄代码）：2584210631-star/mc-scanner、mcprobe、Sandelslover/MCScanner、MineScan 等
