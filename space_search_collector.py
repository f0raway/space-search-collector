#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
space_search_collector.py — FOFA + Hunter + Quake 网络空间测绘资产采集 (独立脚本 + 可被 pipeline 引用)

用法:
  python3 space_search_collector.py                        # 使用默认配置 config.json
  python3 space_search_collector.py -c my_config.json      # 指定配置文件
  python3 space_search_collector.py -o output.txt          # 指定输出文件
  python3 space_search_collector.py -l output.log          # 指定日志文件
  python3 space_search_collector.py -s fofa hunter         # 仅采集指定来源, 默认 all
  python3 space_search_collector.py -s quake               # 默认使用 CIDR 二分 + 断点恢复

配置文件格式 (config.json):
  {
    "sources": "all",
    "output": "assets.txt",
    "logfile": "assets.log",
    "module": {
      "fofa": {
        "url": "https://fofa.info/api/v1/search/all",
        "email": "xxx@qq.com",
        "token": "xxx",
        "full": false,                        # false=近一年数据, true=全部历史
        "interval": 0.5,                      # 每次成功请求后的间隔(秒)
        "retries": 5,                         # 临时错误最大重试次数
        "state_dir": "fofa_cidr_state",       # CIDR 断点续采目录
        "query": "icon_hash==\\"-1200473251\\" || title=\\"hermes studio\\""
      },
      "hunter": {
        "url": "https://hunter.qianxin.com/openApi/search",
        "keys": ["key1", "key2"],
        "all": true,
        "size": 1000,
        "pageSize": 100,
        "query": "web.title=\\"hermes studio\\""
      },
      "quake": {
        "url": "https://quake.360.net/api/v3/search/quake_service",
        "keys": ["key1", "key2"],
        "full_keys": ["实名key"],              # 可选: 中国资产掩码 IP 用实名 key
        "all": true,
        "size": 1000,
        "pageSize": 500,
        "latest": true,
        "interval": 3,
        "adaptive": true,
        "query": "title: \\"hermes studio\\"",
        "partition": {                         # adaptive 为 false 时使用的固定分区
          "geo": [
            {"country": "中国", "provinces": ["北京", "广东"]},
            {"country": "美国", "ports": [80, 443]},
            {"country": "德国"}
          ]
        }
      }
    }
  }

FOFA 采集算法 (CIDR 二分, 突破单次 10000 条上限):
  从 0.0.0.0/0 开始, 每个网段只请求一次 FOFA 看 total:
    total == 0          -> 跳过
    0 < total <= 10000  -> 直接收取本次返回的数据
    total > 10000       -> 二分网段, 继续深入
  断点续采: 每个网段处理完即原子写入 state_dir/state.json, 分片数据存 state_dir/parts/,
  中断/额度耗尽后下次以相同 query 运行会自动从断点恢复; 全部完成后保留断点目录; 新一轮采集请更换 state_dir。

作为模块引用:
  from space_search_collector import load_config, run_collect
  config = load_config("config.json")
  results = run_collect(config)  # 返回合并去重后的资产列表
"""

import base64
import csv
import json
import ipaddress
import os
import random
import ssl
import socket
import sys
import time
from contextlib import ExitStack
from contextvars import ContextVar
from collector_runs import (atomic_text_file as _atomic_text_file,
                            atomic_write_json as _atomic_write_json,
                            exclusive_lock, managed_run)
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from threading import Event, Lock, Thread
from fofa_api import FOFA_FIELDS, parse_row as _fofa_parse_row, fetch as _fetch_fofa, DEFAULT_URL as FOFA_DEFAULT_URL

CTX = ssl.create_default_context()

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/150.0.0.0 Safari/537.36")

TIMEOUT = 60
QUAKE_HEARTBEAT_SECONDS = 5
PRINT_LOCK = Lock()

# 运行期共享结果槽: 各模块采集过程中实时写入, 供中断时抢救部分数据
COLLECT_SINK = {}
_CURRENT_MODULE = None
_ACTIVE_RESULTS = ContextVar("collector_active_results", default=None)


def _module_results():
    """每次调用独立的结果槽; 并发使用不同输出时也不会串入其他调用."""
    active = _ACTIVE_RESULTS.get()
    return active if active is not None else []


def log(msg):
    with PRINT_LOCK:
        print(msg)
        sys.stdout.flush()


# ---- 配置加载 & 模块注册 ----

MODULE_HANDLERS = {}  # {module_name: search_function}


def register_handler(name):
    """装饰器: 注册模块搜索函数"""
    def decorator(fn):
        MODULE_HANDLERS[name] = fn
        return fn
    return decorator


def load_config(path):
    """加载 JSON 配置文件"""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---- HTTP 工具 ----

def _network_error_summary(error):
    """只输出错误类型, 不回显可能含 key 的 URL 或原始异常文本."""
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "网络超时: 连接或读取响应未及时完成; 不能据此判定 key 失效"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "TLS 证书验证失败: 请检查证书信任配置"
    if isinstance(reason, ssl.SSLError):
        return "TLS 连接失败"
    if isinstance(reason, socket.gaierror):
        return "DNS 域名解析失败"
    if isinstance(reason, ConnectionError):
        return "网络连接失败或被中断"
    return f"网络请求失败 ({type(reason).__name__}); 不能据此判定 key 失效"


def http_get(url, params=None, headers=None, timeout=TIMEOUT):
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "ignore")
        except Exception:
            return e.code, ""
    except Exception as e:
        return -1, _network_error_summary(e)


def http_post_json(url, payload, headers=None, timeout=TIMEOUT):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("User-Agent", UA)
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "ignore")
        except Exception:
            return e.code, ""
    except Exception as e:
        return -1, _network_error_summary(e)


# ---- 通用工具 ----

def _is_masked_ip(ip):
    """IP 被平台掩码 (如 120.*.*.*) 时返回 True."""
    return "*" in str(ip or "")


def _resolve_keys(cfg):
    """读取 keys 列表, 兼容旧的单 key 配置."""
    keys = cfg.get("keys")
    if keys is None and "key" in cfg:
        keys = [cfg["key"]]
    if keys is None:
        keys = []
    if isinstance(keys, str):
        keys = [keys]
    if not isinstance(keys, (list, tuple)):
        raise ValueError("keys 必须是字符串列表")
    return list(dict.fromkeys(k.strip() for k in (keys or []) if isinstance(k, str) and k.strip()))


# ---- FOFA (CIDR 二分全量采集) ----

FOFA_LIMIT = 10_000  # FOFA 单次查询返回上限
FOFA_STATE_FILENAME = "state.json"
FOFA_PARTS_DIRNAME = "parts"
FOFA_PART_FIELDS = ["link", "host", "ip", "port", "protocol",
                    "title", "country", "region", "city", "domain"]


def _fofa_build_url(p):
    link = (p.get("link") or "").strip()
    if link:
        return link

    scheme = p["protocol"] if p["protocol"] in ("http", "https") else "http"
    host = (p["ip"] or "").strip() or (p["host"] or "").strip()
    port = p["port"]
    if not host or port is None:
        return None
    # host 字段可能带端口 (如 221.146.11.168:18080), 去掉尾部端口
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":")[0]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def fofa_fetch(cfg, query, size=FOFA_LIMIT, full=False, page=1):
    """保持模块引用接口不变, 请求/解析委托给独立 FOFA API 层."""
    return _fetch_fofa(cfg, query, request_get=http_get, size=size, full=full, page=page)


def _fofa_retryable(error):
    """只重试网络故障、临时服务端错误和短期速率限制; 每日额度耗尽等不重试."""
    lowered = error.lower()
    if any(word in lowered for word in ("daily", "quota", "每日", "次数不足")):
        return False
    if any(word in lowered for word in (
        "http -1", "http 408", "http 429", "json 解析失败",
        "timeout", "timed out", "temporarily unavailable",
    )):
        return True
    return any(f"http {code}" in lowered for code in range(500, 600))


class FofaRequestError(RuntimeError):
    """FOFA 致命错误 (重试耗尽或不可重试). requests 记录本次已消耗的请求数."""
    def __init__(self, message, requests=0):
        super().__init__(message)
        self.requests = requests


def _fofa_query(cfg, query, full, retries):
    """带指数退避重试的 FOFA 查询. 成功返回 (rows, total, 请求数), 失败抛 FofaRequestError."""
    for attempt in range(retries + 1):
        rows, total, err = fofa_fetch(cfg, query, size=FOFA_LIMIT, full=full)
        if not err:
            return rows, total, attempt + 1
        if not _fofa_retryable(err):
            raise FofaRequestError(f"FOFA 返回不可重试错误: {err}", attempt + 1)
        if attempt >= retries:
            raise FofaRequestError(f"FOFA 查询失败, 已重试 {retries} 次: {err}", attempt + 1)
        base_delay = 15 if "HTTP 429" in err else 2
        delay = min(300, base_delay * (2 ** attempt)) + random.uniform(0, 1)
        log(f"[FOFA] {err}; {delay:.1f}s 后重试 (第 {attempt + 1}/{retries} 次)")
        time.sleep(delay)
    raise AssertionError("unreachable")


def _to_cidr(address, prefix_length):
    """32 位整数 + 前缀长度 -> CIDR 字符串."""
    ip = ".".join(str((address >> shift) & 0xFF) for shift in (24, 16, 8, 0))
    return f"{ip}/{prefix_length}"


def _split_cidr(address, prefix_length):
    """二分网段: 左子网下一位为 0, 右子网为 1."""
    child_length = prefix_length + 1
    split_bit = 1 << (32 - child_length)
    return (address, child_length), (address | split_bit, child_length)


def _fofa_load_state(state_dir, base_query, full=False, url=None, email=None):
    """只恢复查询与数据范围匹配的断点; 异常时保留现场, 不删除数据."""
    state_path = os.path.join(state_dir, FOFA_STATE_FILENAME)
    if not os.path.isfile(state_path):
        return None
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        valid = (isinstance(state, dict) and state.get("base_query") == base_query
                 and state.get("full", False) == full
                 and state.get("url", url) == url and state.get("email", email) == email
                 and isinstance(state.get("pending"), list)
                 and isinstance(state.get("completed"), list)
                 and isinstance(state.get("requests"), int)
                 and state.get("limit", FOFA_LIMIT) == FOFA_LIMIT)
        if not valid:
            raise ValueError("断点格式、查询或数据范围不匹配")
        for node in state["pending"]:
            if (not isinstance(node, (list, tuple)) or len(node) != 2
                    or any(type(value) is not int for value in node)
                    or not 0 <= node[0] < 2 ** 32 or not 0 <= node[1] <= 32
                    or node[0] % (1 << (32 - node[1]))):
                raise ValueError("断点网段无效")
        for record in state["completed"]:
            if not isinstance(record, dict):
                raise ValueError("断点记录无效")
            if record.get("status") == "saved":
                file = os.path.realpath(os.path.join(state_dir, record.get("file", "")))
                if os.path.commonpath([os.path.realpath(state_dir), file]) != os.path.realpath(state_dir):
                    raise ValueError("分片路径越界")
        return state
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        raise ValueError("FOFA 断点无法恢复; 原数据已保留, 请更换 state_dir 或备份后移走旧目录") from e


def _fofa_save_part(state_dir, cidr, rows):
    """网段数据落盘为分片 CSV (原子写), 返回相对路径."""
    name = cidr.replace(".", "_").replace("/", "_") + ".csv"
    rel_path = os.path.join(FOFA_PARTS_DIRNAME, name)
    path = os.path.join(state_dir, rel_path)
    with _atomic_text_file(path, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FOFA_PART_FIELDS)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in FOFA_PART_FIELDS})
    return rel_path


def _fofa_ingest(rows, results, seen):
    """FOFA 行 (API dict 或 CSV DictReader 行) -> 标准资产, 去重追加. 返回新增条数."""
    added = 0
    for row in rows:
        r = dict(row)
        if _is_masked_ip(r.get("ip")):
            continue
        port = r.get("port")
        if isinstance(port, str):  # CSV 读回的 port 是字符串
            try:
                r["port"] = int(port)
            except (ValueError, TypeError):
                r["port"] = None
        url = _fofa_build_url(r)
        if not url or url in seen:
            continue
        seen.add(url)
        results.append({
            "host":     url,
            "ip":       r.get("ip") or "",
            "port":     r.get("port"),
            "protocol": r.get("protocol") or "",
            "title":    r.get("title") or "",
            "source":   "fofa",
        })
        added += 1
    return added


def _search_fofa_cidr(cfg):
    """
    FOFA CIDR 二分全量采集, 突破单次 10000 条上限:
      从 0.0.0.0/0 开始, 每个网段只查一次 total:
        total == 0          -> 跳过
        0 < total <= 10000  -> 收取返回数据, 存分片 CSV
        total > 10000       -> 二分网段, 继续深入
    支持断点续采: 每个网段处理完即落盘 state.json, 中断后同查询自动恢复;
    全部完成后保留断点目录; 新一轮采集请更换 state_dir。
    配置字段: url, email, token, query, full(默认 false=近一年), interval, retries, state_dir
    """
    base      = (cfg.get("query") or "").strip()
    full      = cfg.get("full", False)
    interval  = cfg.get("interval", 0.5)
    retries   = cfg.get("retries", 5)
    state_dir = cfg.get("state_dir", "fofa_cidr_state")

    log(f"[FOFA] 语法: {base}")
    log(f"[FOFA] CIDR 二分采集, full={full}, interval={interval}s, "
        f"retries={retries}, 断点目录: {state_dir}")

    results = _module_results()
    seen = set()

    state = _fofa_load_state(state_dir, base, full, cfg["url"], cfg["email"])
    if state is not None:
        log(f"[FOFA] 恢复断点: 已完成 {len(state['completed'])} 个网段, "
            f"累计 {state['requests']} 次请求")
        # 已完成网段的数据从分片 CSV 读回, 不重复消耗 API
        for rec in state["completed"]:
            if rec.get("status") != "saved":
                continue
            path = os.path.join(state_dir, rec.get("file", ""))
            if not os.path.isfile(path):
                raise ValueError("FOFA 断点分片缺失; 原断点已保留, 请恢复分片或更换 state_dir")
            with open(path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if reader.fieldnames != FOFA_PART_FIELDS:
                    raise ValueError("FOFA 分片字段损坏; 原文件已保留")
                _fofa_ingest(reader, results, seen)
        log(f"[FOFA] 断点数据载入: {len(results)} 条")
    else:
        state = {"version": 1, "limit": FOFA_LIMIT, "auto_resume": True, "base_query": base, "full": full, "url": cfg["url"], "email": cfg["email"],
                 "pending": [[0, 0]], "completed": [], "requests": 0}
        os.makedirs(os.path.join(state_dir, FOFA_PARTS_DIRNAME), exist_ok=True)
        _atomic_write_json(os.path.join(state_dir, FOFA_STATE_FILENAME), state)

    stack = [tuple(node) for node in state["pending"]]
    state_path = os.path.join(state_dir, FOFA_STATE_FILENAME)

    while stack:
        # 成功处理前不弹出栈顶; 中断后该节点仍保留在状态文件中
        address, prefix_length = stack[-1]
        cidr = _to_cidr(address, prefix_length)
        query = f'({base}) && ip="{cidr}"'

        try:
            rows, total, reqs = _fofa_query(cfg, query, full, retries)
        except FofaRequestError as e:
            state["requests"] += e.requests
            _atomic_write_json(state_path, state)
            raise

        state["requests"] += reqs
        if interval > 0:
            time.sleep(interval)

        stack.pop()
        if total == 0:
            state["completed"].append({"cidr": cidr, "total": 0, "status": "empty"})
            log(f"[FOFA] {cidr}: 空 (已扫 {len(state['completed'])} 段, 累计 {len(results)} 条)")
        elif total <= FOFA_LIMIT:
            if len(rows) < total:
                raise FofaRequestError("FOFA 返回条数少于 total; 保留当前断点, 避免遗漏数据")
            part = _fofa_save_part(state_dir, cidr, rows)
            added = _fofa_ingest(rows, results, seen)
            state["completed"].append({
                "cidr": cidr, "total": total, "rows": len(rows),
                "file": part, "status": "saved",
            })
            log(f"[FOFA] {cidr}: {total} 条, 新增 {added} "
                f"(已扫 {len(state['completed'])} 段, 累计 {len(results)} 条)")
        elif prefix_length == 32:
            part = _fofa_save_part(state_dir, cidr, rows)
            _fofa_ingest(rows, results, seen)
            state["completed"].append({
                "cidr": cidr, "total": total, "rows": len(rows), "file": part, "status": "saved",
            })
            log(f"[FOFA] [!] {cidr} 已是单个 IP 仍有 {total} 条, 无法继续二分, 超出部分丢失")
        else:
            left, right = _split_cidr(address, prefix_length)
            # 栈后进先出: 右侧先入栈, 左侧先执行
            stack.append(right)
            stack.append(left)
            log(f"[FOFA] {cidr}: {total} 条 > {FOFA_LIMIT}, 二分")

        state["pending"] = [list(node) for node in stack]
        _atomic_write_json(state_path, state)

    state["merged"] = _fofa_merge_parts(state, state_dir)
    state["auto_resume"] = False
    _atomic_write_json(state_path, state)
    # 保留分片及原始字段 CSV, 输出失败时可恢复.
    log(f"[FOFA] CIDR 采集完成: {len(results)} 条, 共 {state['requests']} 次请求, 断点目录已保留")
    return results


def _fofa_merge_parts(state, directory):
    """流式合并 FOFA 原始字段, 不经 URL 去重或丢弃无法构造 URL 的行."""
    output = os.path.join(directory, "fofa_merged.csv")
    count = 0
    parts = 0
    with _atomic_text_file(output, newline="") as target:
        writer = csv.DictWriter(target, fieldnames=FOFA_PART_FIELDS)
        writer.writeheader()
        for record in state["completed"]:
            if record.get("status") != "saved":
                continue
            path = os.path.realpath(os.path.join(directory, record["file"]))
            if os.path.commonpath([os.path.realpath(directory), path]) != os.path.realpath(directory):
                raise ValueError("FOFA 分片路径越界")
            with open(path, newline="", encoding="utf-8") as source:
                reader = csv.DictReader(source)
                if reader.fieldnames != FOFA_PART_FIELDS:
                    raise ValueError("FOFA 分片字段损坏; 原文件已保留")
                for row in reader:
                    writer.writerow({key: row.get(key, "") for key in FOFA_PART_FIELDS})
                    count += 1
            parts += 1
    log(f"[FOFA] 原始字段 CSV: {output} ({count} 行, {parts} 个分片)")
    return {"file": "fofa_merged.csv", "rows": count, "parts": parts}


def _managed_engine(source, cfg, engine):
    if source == "fofa":
        cfg = dict(cfg, url=cfg.get("url") or FOFA_DEFAULT_URL)
    if cfg.get("run_mode", "auto") == "fixed":
        if cfg.get("new_run") or cfg.get("resume_dir"):
            raise ValueError("--new / --resume 需要 run_mode=auto")
        # 显式兼容旧的固定目录/完成缓存行为.
        with exclusive_lock(os.path.join(_prepare_fixed_dir(cfg, source), '.run.lock')):
            return engine(cfg)
    if cfg.get("run_mode", "auto") != "auto":
        raise ValueError("run_mode 只支持 auto 或 fixed")
    if source == "fofa":
        identity = {"query": (cfg.get("query") or "").strip(), "url": cfg["url"],
                    "email": cfg["email"], "full": cfg.get("full", False)}
    else:
        identity = _quake_state_identity(cfg)
    parent = cfg.get("state_dir", source + "_cidr_state")
    with managed_run(source, parent, identity, new=cfg.get("new_run", False),
                     resume=cfg.get("resume_dir"), logger=log) as run:
        return engine(dict(cfg, state_dir=run.directory))


def _prepare_fixed_dir(cfg, source):
    directory = cfg.get("state_dir", source + "_cidr_state")
    os.makedirs(directory, exist_ok=True)
    return directory


@register_handler("fofa")
def search_fofa(cfg):
    return _managed_engine("fofa", cfg, _search_fofa_cidr)


# ---- Hunter ----

@register_handler("hunter")
def search_hunter(cfg):
    query     = cfg["query"]
    all_res   = cfg.get("all", True)
    size      = cfg.get("size", 1000)
    page_size = cfg.get("pageSize", 100)  # 单次最多 100, 拉取更快
    keys      = _resolve_keys(cfg)         # 多 key 轮巡

    if not keys:
        log("[Hunter] [!] 未配置 key 或 keys, 跳过")
        return []

    log(f"[Hunter] 语法: {query}")
    log(f"[Hunter] all={all_res}, size={size}, pageSize={page_size}, keys={len(keys)}")

    max_pages = (size + page_size - 1) // page_size if not all_res else 10000
    results = _module_results()
    seen = set()
    next_page = 1
    stop = False
    key_idx = 0
    consecutive_fail = 0
    dead = set()

    def _hunter_page(page, api_key):
        encoded = base64.urlsafe_b64encode(query.encode("utf-8")).decode("ascii").rstrip("=")
        params = {
            "api-key":   api_key,
            "search":    encoded,
            "page":      page,
            "page_size": page_size,
            "is_web":    "1",
        }
        code, text = http_get(cfg["url"], params=params)
        if code != 200:
            return page, code, text, None, api_key
        try:
            return page, code, text, json.loads(text), api_key
        except Exception:
            return page, code, text, None, api_key

    failure_limit = max(10, len(keys) * 3)
    while next_page <= max_pages and not stop and consecutive_fail < failure_limit:
        available = [k for k in keys if k not in dead]
        if not available:
            log("[Hunter] [!] 所有 key 积分耗尽或认证失败, 停止")
            break
        api_key = available[key_idx % len(available)]

        page, code, text, data, used_key = _hunter_page(next_page, api_key)
        key_short = f"#{keys.index(used_key) + 1}"

        if code in (401, 403):
            dead.add(api_key)
            continue
        if code != 200 or not isinstance(data, dict) or not data:
            log(f"[Hunter] page={page} HTTP {code} key={key_short}")
            consecutive_fail += 1
            key_idx += 1
            time.sleep(min(30, 2 ** min(consecutive_fail - 1, 5)))
            continue

        api_code = data.get("code")
        if api_code == 40204:
            dead.add(api_key)
            log(f"[Hunter] page={page} key={key_short} 积分用完, 换 key")
            continue

        if api_code != 200:
            msg = str(data.get("message") or "")
            if any(word in msg.lower() for word in (
                "无 api", "无api", "访问权限", "付费账号", "api权限", "api 权限",
                "无权限", "权限不足", "key无效", "key 无效", "认证失败", "已过期",
            )):
                dead.add(api_key)
                log(f"[Hunter] page={page} key={key_short} 无权限或凭据失效, 本轮排除并换 key")
                continue
            if any(kw in msg.lower() for kw in ("请求太多", "太多啦")):
                log(f"[Hunter] page={page} 限流, 等待 3s")
                consecutive_fail += 1
                key_idx += 1
                time.sleep(3)
                continue
            log(f"[Hunter] page={page} key={key_short} API code={api_code} msg={msg}")
            key_idx += 1
            consecutive_fail += 1
            continue

        payload = data.get("data") or {}
        arr = payload.get("arr") or []
        total = payload.get("total", 0)
        page_assets = 0
        for asset in arr:
            if not all_res and len(results) >= size:
                break
            url = asset.get("url") or ""
            if url and url not in seen:
                seen.add(url)
                results.append({
                    "host":     url,
                    "ip":       str(asset.get("ip") or ""),
                    "port":     asset.get("port"),
                    "protocol": asset.get("protocol") or "",
                    "title":    asset.get("web_title") or "",
                    "source":   "hunter",
                })
                page_assets += 1

        log(f"[Hunter] page={page} key={key_short} 新增 {page_assets} 条 (累计 {len(results)}, total={total})")
        consecutive_fail = 0
        next_page += 1

        if len(arr) < page_size:
            stop = True
        elif not all_res and len(results) >= size:
            stop = True
        elif next_page > max_pages:
            stop = True

    if consecutive_fail >= failure_limit:
        log("[Hunter] [!] 持续失败, 本次只保留已取得结果, 尚未完成全部翻页")
    elif all_res and not stop and next_page > max_pages:
        log("[Hunter] [!] 达到安全翻页上限, 结果可能不完整")
    return results


# ---- Quake (360) ----

# Quake API v3 的错误 code 为字符串 (如 "q2001"), 成功时 code 为 0。
# 由于官方未公开完整错误码表, 这里按 code + message 关键词综合判定。
def _quake_error_action(api_code, msg):
    """返回 Quake 错误的处理动作: ok/limit/permission/quota/rate/param/token/unknown"""
    code_s = str(api_code)
    if api_code == 0 or code_s == "0":
        return "ok"
    m = (msg or "")
    # 优先按 message 区分翻页窗口与权限; 同一码可能对应不同错误
    if "最大允许" in m or "超出" in m:
        return "limit"
    # 权限不足 -> 该 key 不可用
    if "权限" in m or "缺少" in m:
        return "permission"
    # 积分/额度 -> 该 key 不可用
    if any(k in m for k in ("积分", "余额", "额度", "点数", "quota")):
        return "quota"
    # 限流 -> 退避换 key
    if any(k in m for k in ("频繁", "太多", "限流", "rate")):
        return "rate"
    # 参数错误 -> 停止
    if any(k in m for k in ("参数", "语法", "param")):
        return "param"
    # token 问题 -> 该 key 不可用
    if any(k in m.lower() for k in ("token", "认证", "登录", "过期", "失效")):
        return "token"
    # 无法从 message 判断时, 按 code 兜底
    if code_s == "q2001":
        return "permission"
    if code_s == "q2002":
        return "quota"
    if code_s in ("q2003", "q3005"):
        return "rate"
    if code_s == "q2004":
        return "param"
    return "unknown"


def _build_quake_queries(cfg):
    """
    根据基础 query 和 partition 生成子查询列表.
    partition.geo 每个条目三种写法:
      {"country": "中国", "provinces": ["北京", "广东", ...]}   -> 按省份展开 (country+province)
      {"country": "美国", "ports": [80, 443, 8080, ...]}        -> 按端口展开 (country+port)
      {"country": "德国"}                                       -> 仅按国家 (country)
    生成: base && country:"中国" && province:"北京" 等
    """
    base = (cfg.get("query") or cfg.get("base_query") or "").strip()
    if not base:
        return []

    partition = cfg.get("partition") or {}
    geo = partition.get("geo") or []
    if not geo:
        return [base]

    queries = []
    for g in geo:
        country = (g.get("country") or "").strip()
        provinces = g.get("provinces") or []
        ports = g.get("ports") or []

        def _join(prov=None, port=None):
            q = f"({base})"
            if country:
                q += f' && country:"{country}"'
            if prov:
                q += f' && province:"{prov}"'
            if port is not None:
                q += f' && port:{port}'
            return q

        if provinces:
            for prov in provinces:
                queries.append(_join(prov=(prov or "").strip()))
        elif ports:
            for port in ports:
                queries.append(_join(port=port))
        else:
            queries.append(_join())
    return queries


def _quake_parse_item(item):
    """解析 Quake 单条结果 -> 资产信息 (含地域/端口, 供分布分析)."""
    service = item.get("service") or {}
    http_info = service.get("http") or {}
    loc = item.get("location") or {}
    ip = str(item.get("ip") or "")
    port = item.get("port")
    proto = http_info.get("protocol") or item.get("protocol") or ""
    has_tls = service.get("tls") is not None
    scheme = "https" if (has_tls or "https" in str(proto).lower() or port == 443) else "http"
    return {
        "ip":       ip,
        "port":     port,
        "hostname": item.get("hostname") or "",
        "title":    http_info.get("title") or "",
        "scheme":   scheme,
        "country":  loc.get("country_cn") or "",
        "province": loc.get("province_cn") or "",
        "city":     loc.get("city_cn") or "",
    }


def _quake_build_url(p):
    host = p["hostname"] or p["ip"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f'{p["scheme"]}://{host}:{p["port"]}'


def _quake_request(url, payload, api_key, key_label, phase, timeout):
    """同步请求保留 Ctrl+C 行为, 后台线程仅输出等待心跳, 不执行网络操作."""
    started = time.monotonic()
    done = Event()
    label = f"[Quake][{phase}] key={key_label} start={payload['start']}"
    log(f"{label} 开始请求, 条数={payload['size']}, 超时设置={timeout}s")

    def heartbeat():
        while not done.wait(QUAKE_HEARTBEAT_SECONDS):
            log(f"{label} 等待响应 {time.monotonic() - started:.0f}s; 尚不能判断 key 状态")

    thread = Thread(target=heartbeat, name="quake-progress", daemon=True)
    thread.start()
    try:
        code, text = http_post_json(url, payload, headers={"X-QuakeToken": api_key}, timeout=timeout)
    except BaseException:
        log(f"{label} 请求中断, 用时 {time.monotonic() - started:.1f}s")
        raise
    finally:
        done.set()
        thread.join()

    elapsed = time.monotonic() - started
    if code == -1:
        # http_post_json 已将网络异常转换成不含凭据的分类信息.
        detail = "网络请求失败; 未收到可用于判断 key 的 HTTP 响应"
        if any(word in text for word in ("超时", "Timeout")):
            detail = "网络超时; 不能据此判定 key 失效"
        elif "DNS" in text:
            detail = "DNS 域名解析失败"
        elif "TLS" in text:
            detail = "TLS 连接或证书验证失败"
        log(f"{label} {detail}, 用时 {elapsed:.1f}s")
    elif code != 200:
        detail = {401: "认证失败", 403: "访问被拒绝, 需检查权限或访问策略",
                  429: "服务端限流"}.get(code, "服务端/网关响应异常")
        log(f"{label} HTTP {code}: {detail}, 用时 {elapsed:.1f}s")
    else:
        try:
            data = json.loads(text)
            action = _quake_error_action(data.get("code"), data.get("message", ""))
            detail = {"ok": "成功", "limit": "翻页或返回条数受限", "permission": "账号无搜索权限",
                      "quota": "额度不足", "rate": "接口限流", "param": "查询参数错误",
                      "token": "凭据认证失败", "unknown": "未知 API 错误"}[action]
            log(f"{label} 收到响应: {detail}, API code={data.get('code')}, 用时 {elapsed:.1f}s")
        except (ValueError, TypeError, AttributeError):
            log(f"{label} HTTP 200 但响应格式异常, 用时 {elapsed:.1f}s")
    return code, text


class _QuakeRequester:
    """采样、翻页、子查询和失败重试共享请求间隔及限流退避."""
    def __init__(self, interval):
        self.interval = interval
        self.gap = interval
        self.finished = None

    def __call__(self, url, payload, api_key, key_label, phase, timeout):
        if self.finished is not None:
            remaining = self.finished + self.gap - time.monotonic()
            if remaining > 0:
                log(f"[Quake] 请求节流: 等待 {remaining:.1f}s 后继续 ({phase})")
                time.sleep(remaining)
        try:
            code, text = _quake_request(url, payload, api_key, key_label, phase, timeout)
        finally:
            self.finished = time.monotonic()
        rate = code == 429
        if code == 200:
            try:
                data = json.loads(text)
                rate = _quake_error_action(data.get("code"), data.get("message", "")) == "rate"
            except (ValueError, TypeError, AttributeError):
                pass
        if rate:
            self.gap = max(self.interval, min(30, max(3, self.gap * 2)))
            log(f"[Quake] 检测到限流, 后续请求间隔调整为 {self.gap:.1f}s (跨 key 生效)")
        elif code == 200:
            self.gap = max(self.interval, self.gap * 0.8)
        return code, text


def _quake_refine_queries(query, rows):
    """按尚未使用的地域/端口维度分区, NOT 尾查询保留未采样值与缺失值."""
    parsed = [_quake_parse_item(row) for row in rows if isinstance(row, dict)]
    for field, name in (("country", "country"), ("province", "province"), ("port", "port")):
        if f"{field}:" in query:
            continue
        values = list(dict.fromkeys(item[name] for item in parsed if item[name] not in (None, "")))[:32]
        if not values:
            continue
        clauses = [f"{field}:{value}" if field == "port" else
                   f"{field}:" + json.dumps(value, ensure_ascii=False) for value in values]
        return ([f"({query}) && {clause}" for clause in clauses]
                + [f"({query}) && NOT (" + " || ".join(clauses) + ")"])
    return []


def _quake_ingest(rows, results, seen):
    counts = {"added": 0, "masked": 0, "invalid": 0, "duplicate": 0}
    for item in rows:
        if not isinstance(item, dict):
            counts["invalid"] += 1
            continue
        parsed = _quake_parse_item(item)
        # 掩码 IP 配有可解析 hostname 时仍能作为有效 URL 保留.
        if _is_masked_ip(parsed["ip"]) and not parsed["hostname"]:
            counts["masked"] += 1
            continue
        if not (parsed["hostname"] or parsed["ip"]) or parsed["port"] is None:
            counts["invalid"] += 1
            continue
        url = _quake_build_url(parsed)
        if not parse_url_key({"host": url}):
            counts["invalid"] += 1
            continue
        if url in seen:
            counts["duplicate"] += 1
            continue
        seen.add(url)
        results.append({"host": url, "ip": "" if _is_masked_ip(parsed["ip"]) else parsed["ip"],
                        "port": parsed["port"], "protocol": parsed["scheme"],
                        "title": parsed["title"], "source": "quake"})
        counts["added"] += 1
    return counts


def _quake_fetch_page(url, api_key, query, start, page_size, latest, timeout=TIMEOUT, key_label="未编号", requester=None):
    """单次请求 Quake, 返回解析后的 JSON dict, 失败返回 None."""
    payload = {"query": query, "start": start, "size": page_size,
               "ignore_cache": False, "latest": latest}
    code, text = (requester or _quake_request)(url, payload, api_key, key_label, "采样", timeout)
    if code != 200:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _adaptive_quake_queries(cfg, url, keys, latest, page_size):
    """采样 + 分析分布(国家/省份/端口) + 生成子查询 (含 NOT 反选尾覆盖长尾)."""
    from collections import Counter

    base = "(" + (cfg.get("query") or cfg.get("base_query") or "") + ")"
    sample = []
    base_total = 0

    # 采样: 取前 2 页 (每页 page_size, 共 up to 1000 条)
    for start in (0, page_size):
        data = None
        for api_key in keys:
            candidate = _quake_fetch_page(url, api_key, base, start, page_size, latest,
                                          timeout=cfg.get("timeout", 30), key_label=f"#{keys.index(api_key) + 1}",
                                          requester=cfg.get("_requester"))
            if candidate and str(candidate.get("code")) == "0":
                data = candidate
                break
            log(f"[Quake][采样] key=#{keys.index(api_key) + 1} 未取得有效样本, 尝试下一个 key")
        if not data:
            break
        rows = data.get("data") or []
        if isinstance(cfg.get("_sample_rows"), list):
            cfg["_sample_rows"].extend(rows)
        sample.extend(_quake_parse_item(r) for r in rows)
        base_total = (data.get("meta") or {}).get("pagination", {}).get("total", base_total)
        if len(rows) < page_size:
            break

    if not sample:
        log("[Quake][采样] 未取得样本, 转为原查询采集")
        return [base]

    sample_size = len(sample)
    country_counter = Counter(it["country"] for it in sample if it["country"])

    queries = []
    for country, cnt in sorted(country_counter.items(), key=lambda kv: -kv[1]):
        est_total = int(cnt / sample_size * base_total) if base_total else cnt
        if est_total < 1000:
            queries.append(f'{base} && country:"{country}"')
        elif country == "中国":
            prov_counter = Counter(it["province"] for it in sample
                                   if it["country"] == "中国" and it["province"])
            for p in prov_counter:
                queries.append(f'{base} && country:"中国" && province:"{p}"')
            if prov_counter:
                excluded = " || ".join(f'province:"{p}"' for p in prov_counter)
                queries.append(f'{base} && country:"中国" && NOT ({excluded})')
            else:
                queries.append(f'{base} && country:"中国"')
        else:
            port_counter = Counter(it["port"] for it in sample
                                   if it["country"] == country and it["port"] is not None)
            for p in port_counter:
                queries.append(f'{base} && country:"{country}" && port:{p}')
            if port_counter:
                excluded = " || ".join(f'port:{p}' for p in port_counter)
                queries.append(f'{base} && country:"{country}" && NOT ({excluded})')
            else:
                queries.append(f'{base} && country:"{country}"')

    # NOT 反选尾: 排除采样覆盖的所有国家, 抓长尾国家 + 无国家字段的结果
    if country_counter:
        not_clause = " || ".join(f'country:"{c}"' for c in country_counter)
        queries.append(f'{base} && NOT ({not_clause})')

    log(f"[Quake][采样] 完成, 样本 {len(sample)} 条, 生成 {len(queries) or 1} 个子查询")
    return queries or [base]


def _search_quake_partitioned(cfg):
    """
    Quake (360 空间测绘) 搜索, 支持分区/自适应采样 + NOT 反选, 自动丢弃掩码 IP.
    配置字段: url, keys(多 key 轮巡), full_keys(实名 key, 查中国资产完整 IP),
              query(基础语法), adaptive(采样分析), partition(固定分区),
              all(默认 true, 不以 size 截断), size(all=false 时生效), pageSize, latest, interval
    认证: 请求头 X-QuakeToken, POST JSON body {query, start, size, latest}
    注意: all=true 不使用 size 截断, 仍受实际账号的接口权限、额度及翻页上限限制.
    """
    query     = cfg.get("query") or cfg.get("base_query") or ""
    size      = cfg.get("size", 1000)      # all=false 时的每个子查询采集上限
    all_res   = cfg.get("all", True)
    page_size = cfg.get("pageSize", 500)   # 单次最多 500
    latest    = cfg.get("latest", True)    # 基础会员仅支持最新数据, 默认 true
    interval  = cfg.get("interval", 3)     # 每次请求间隔(秒), 降低限流风险
    timeout   = cfg.get("timeout", 30)
    retries   = cfg.get("retries", 5)
    request_size = page_size
    window = cfg.get("window", 1000)
    max_partitions = cfg.get("max_partitions", 100000)
    requester = _QuakeRequester(interval)
    keys      = _resolve_keys(cfg)

    if not keys:
        log("[Quake] [!] 未配置 key 或 keys, 跳过")
        return []

    # 实名 key (返回完整 IP): 中国资产用普通 key 会被掩码, 需用实名 key 查询
    full_keys = _resolve_keys({"keys": cfg.get("full_keys")})
    if full_keys:
        log(f"[Quake] 实名 key (完整IP) {len(full_keys)} 个")

    log(f"[Quake] 初始化: keys={len(keys)}, pageSize={page_size}, timeout={timeout}s, adaptive={bool(cfg.get('adaptive'))}")
    sample_rows = []
    # 子查询: 优先 adaptive 采样分析; 否则用 partition; 都没有则单查询
    if cfg.get("adaptive"):
        sub_queries = _adaptive_quake_queries(dict(cfg, _requester=requester, _sample_rows=sample_rows), cfg["url"], keys, latest, page_size)
    else:
        sub_queries = _build_quake_queries(cfg)
    if not sub_queries:
        log("[Quake] [!] 无有效查询, 跳过")
        return []

    log(f"[Quake] 基础语法: {query}")
    log(f"[Quake] 子查询 {len(sub_queries)} 个, all={all_res}, size={size}/子查询(all=false生效), pageSize={page_size}, latest={latest}, interval={interval}s, keys={len(keys)}")

    results = _module_results()
    seen = set()
    dead = set()        # 已失效的 key (token 错误 / 额度用完)
    rate_sleep = 1
    retry_count = 0
    key_idx = 0         # 轮巡指针, 每次请求换下一个可用 key, 摊薄限流与积分

    if sample_rows:
        stats = _quake_ingest(sample_rows, results, seen)
        log(f"[Quake] 复用采样数据: 新增 {stats['added']}, 掩码无主机名 {stats['masked']}, 无效 {stats['invalid']}, 重复 {stats['duplicate']}")
    all_keys = list(dict.fromkeys(keys + full_keys))
    sub_queries = list(dict.fromkeys(sub_queries))
    queued = set(sub_queries)
    masked_by_country = {}
    preferred = {}
    incomplete = set()

    def refine(query, rows):
        children = _quake_refine_queries(query, rows) if all_res else []
        children = [child for child in children if child not in queued]
        if children and len(queued) + len(children) <= max_partitions:
            queued.update(children)
            sub_queries.extend(children)
            log(f"[Quake] 查询超过可翻页窗口, 自动细分 {len(children)} 个查询 (含未采样值的 NOT 尾分区)")
        else:
            incomplete.add(query)
            log("[Quake] [!] 已达可翻页窗口, 无可用细分维度或已达分区数量上限; 此查询未完整采集")

    for qi, query in enumerate(sub_queries):
        start = 0
        total = None
        rate_failures = 0
        network_failures = 0
        buffered_rows = []
        country_scope = None
        for country in masked_by_country.keys() | preferred.keys() | {"中国"}:
            if f'&& country:"{country}"' in query:
                country_scope = country
                break
        forced_key = None
        # 中国资产子查询 -> 用实名 key (未实名 key 返回掩码 IP)
        key_pool = list(dict.fromkeys((full_keys + keys) if (full_keys and 'country:"中国"' in query) else (keys + full_keys)))
        if country_scope == "中国" and full_keys:
            forced_key = next((key for key in full_keys if key not in dead), None)

        while True:
            unavailable_masks = masked_by_country.get(country_scope, set()) if country_scope else set()
            available = [k for k in key_pool if k not in dead and k not in unavailable_masks]
            if not available and unavailable_masks:
                incomplete.add(query)
                log(f"[Quake] [!] {country_scope} 分区: 本轮已测试的全部 key 对该国采样页均返回掩码, 跳过重复查询; 请配置有完整 IP 权限的 full_keys")
                break
            if not available:
                log("[Quake] [!] 所有 key 均已失效或额度用完, 停止")
                return results

            api_key = (forced_key if forced_key in available else
                       preferred.get(country_scope) if preferred.get(country_scope) in available else
                       available[key_idx % len(available)])
            forced_key = None
            key_short = f"#{all_keys.index(api_key) + 1}"

            payload = {
                "query":        query,
                "start":        start,
                "size":         min(request_size, window - start) if all_res else min(request_size, size - start, window - start),
                "ignore_cache": False,
                "latest":       latest,
            }
            code, text = requester(cfg["url"], payload, api_key, key_short,
                                        f"采集 {qi+1}/{len(sub_queries)}", timeout)

            if code != 200:
                log(f"[Quake] 子查询{qi+1} start={start} key={key_short} HTTP {code}: {text[:200]}")
                if code in (401, 403):
                    log(f"[Quake] key={key_short} 认证失败, 弃用该 key")
                    dead.add(api_key)
                    retry_count = 0
                    continue
                network_failures += 1
                key_idx += 1
                if code == -1 or code in (408, 413, 504):
                    request_size = max(1, request_size // 2)
                if network_failures > retries:
                    log(f"[Quake] [!] 当前页网络失败, 重试 {retries} 次仍未恢复; 停止并保留部分结果, 不判定 key 失效")
                    return results
                delay = min(30, 2 ** (network_failures - 1))
                log(f"[Quake] {delay}s 后换 key 重试同页, 每页 {request_size} 条")
                time.sleep(delay)
                continue

            try:
                data = json.loads(text)
                if not isinstance(data, dict):
                    raise ValueError("响应不是 JSON 对象")
            except (ValueError, TypeError):
                network_failures += 1
                key_idx += 1
                if network_failures > retries:
                    log("[Quake] [!] 响应持续异常, 停止并保留结果; 未判定 key 失效")
                    return results
                delay = min(30, 2 ** (network_failures - 1))
                log(f"[Quake] 响应格式异常, {delay}s 后换 key 重试同页")
                time.sleep(delay)
                continue

            api_code = data.get("code")
            msg = data.get("message", "")
            if api_code != 0 and str(api_code) != "0":
                action = _quake_error_action(api_code, msg)
                if action == "limit":
                    log(f"[Quake] 子查询{qi+1} 已触发翻页限制, 停止同页轮换全部 key, 转为缩小查询")
                    if start > 0:
                        window = min(window, start)
                    refine(query, buffered_rows)
                    break
                if action == "permission":
                    log(f"[Quake] key={key_short} 账号缺少 API 搜索权限 (code={api_code} {msg}), 弃用该 key")
                    dead.add(api_key)
                    retry_count = 0
                    continue
                if action in ("token", "quota"):
                    log(f"[Quake] key={key_short} {action} (code={api_code} {msg}), 弃用该 key")
                    dead.add(api_key)
                    retry_count = 0
                    continue
                if action == "rate":
                    rate_failures += 1
                    if rate_failures >= max(10, len(key_pool) * 3):
                        log("[Quake] 持续限流, 停止本次采集并保留已采集数据")
                        return results
                    log(f"[Quake] key={key_short} 请求过于频繁 (code={api_code}), 等待 {rate_sleep}s 后换下一个 key")
                    key_idx += 1
                    time.sleep(rate_sleep)
                    rate_sleep = min(rate_sleep * 2, 30)
                    continue
                if action == "param":
                    log(f"[Quake] 子查询{qi+1} 语法/参数错误 (code={api_code} {msg}), 跳过该子查询")
                    break
                # 未知错误: 退避重试, 重试过多弃用 key
                log(f"[Quake] start={start} key={key_short} API code={api_code} msg={msg}, 等待 {rate_sleep}s")
                time.sleep(rate_sleep)
                rate_sleep = min(rate_sleep * 2, 30)
                retry_count += 1
                if retry_count >= 8:
                    log(f"[Quake] key={key_short} 连续失败过多, 弃用")
                    dead.add(api_key)
                    retry_count = 0
                continue

            network_failures = 0
            rate_sleep = 1
            rate_failures = 0
            retry_count = 0
            key_idx += 1   # 成功一次就轮巡到下一个 key

            rows = data.get("data") or []
            meta = data.get("meta") or {}
            pagination = meta.get("pagination") or {}
            total = pagination.get("total", 0)

            buffered_rows.extend(rows)
            counts = _quake_ingest(rows, results, seen)
            log(f"[Quake] 子查询{qi+1}/{len(sub_queries)} key={key_short} start={start} "
                f"收到 {len(rows)} 条: 新增 {counts['added']}, 掩码无主机名 {counts['masked']}, "
                f"无效 {counts['invalid']}, 重复 {counts['duplicate']} (total={total}, 累计 {len(results)})")

            countries = {_quake_parse_item(row)["country"] for row in rows if isinstance(row, dict)} - {""}
            page_country = next(iter(countries)) if len(countries) == 1 else country_scope
            if page_country and counts["masked"] == len(rows) and rows:
                known_masked = masked_by_country.setdefault(page_country, set())
                known_masked.add(api_key)
                candidates = [key for key in key_pool if key not in dead and key not in known_masked]
                if candidates:
                    forced_key = candidates[0]
                    log(f"[Quake] {page_country} 本页全部被掩码, 在当前页探测其他 key 的完整地址权限; 已测试 {len(known_masked)}/{len(key_pool)}")
                    continue
                incomplete.add(query)
                if country_scope:
                    log(f"[Quake] [!] {page_country} 全部 key 对该国本轮测试页均返回掩码, 后续同国分区复用此诊断; 需要 full_keys 完整地址权限")
                    break
            elif page_country and counts["added"] + counts["duplicate"] > 0:
                preferred[page_country] = api_key
            if counts["masked"] and (not page_country or counts["masked"] < len(rows)):
                incomplete.add(query)
                log("[Quake] [!] 本页部分地址被掩码, 可补充有完整 IP 权限的 full_keys; 已保留可用地址")

            if total > window and all_res:
                refine(query, buffered_rows)
                break

            start += len(rows)

            if not rows:
                break
            if total and start >= total:
                break
            if len(rows) < payload["size"]:
                break
            if not all_res and start >= size:
                break

            if start >= window:
                refine(query, buffered_rows)
                break

    log(f"[Quake] 采集结束, 累计 {len(results)} 条, 仍有 {len(incomplete)} 个查询受掩码/窗口限制未确认完整")
    return results


class QuakeCollectionError(RuntimeError):
    """本轮不能继续请求; 保留待处理任务供下次恢复."""


class _QuakeClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.keys = list(dict.fromkeys(_resolve_keys({'keys': cfg.get('full_keys')}) + _resolve_keys(cfg)))
        self.dead = set()
        self.preferred = None
        self.cursor = 0
        self.requester = _QuakeRequester(cfg.get('interval', 3))
        self.timeout = cfg.get('timeout', 30)
        self.requests = 0
        self.target_page_size = min(500, cfg.get('pageSize', 500))
        self.page_size = self.target_page_size
        self.min_page_size = min(self.target_page_size, cfg.get('min_page_size', 50))
        self.success_streak = 0

    def fetch(self, query, start, size, phase, excluded=None):
        excluded = excluded or set()
        failures = 0
        rates = 0
        retries = self.cfg.get('retries', 5)
        while True:
            available = [key for key in self.keys if key not in self.dead and key not in excluded]
            if not available:
                raise QuakeCollectionError('没有可用 key (权限/额度/掩码), 待处理任务已保留')
            key = self.preferred if self.preferred in available else available[self.cursor % len(available)]
            self.cursor += 1
            payload = {'query': query, 'start': start, 'size': min(size, self.page_size),
                       'ignore_cache': False, 'latest': self.cfg.get('latest', True)}
            self.requests += 1
            code, text = self.requester(self.cfg['url'], payload, key,
                                        f'#{self.keys.index(key) + 1}', phase, self.timeout)
            if code in (401, 403):
                self.dead.add(key)
                log(f'[Quake] key=#{self.keys.index(key)+1} 认证/访问被拒绝, 换 key 接续 start={start}')
                continue
            try:
                data = json.loads(text) if code == 200 else None
                if not isinstance(data, dict):
                    raise ValueError('响应格式异常')
            except (ValueError, TypeError):
                failures += 1
                self.preferred = None
                if code == -1 or code in (408, 413, 504):
                    self.page_size = max(self.min_page_size, self.page_size // 2)
                    self.success_streak = 0
                if failures > retries:
                    raise QuakeCollectionError('网络或响应持续异常; 不判定 key 失效')
                delay = min(30, 2 ** (failures - 1))
                log(f'[Quake] 网络/响应异常, {delay}s 后同页重试, 每页 {self.page_size} 条')
                time.sleep(delay)
                continue
            action = _quake_error_action(data.get('code'), data.get('message', ''))
            if action == 'ok':
                rows = data.get('data')
                total = ((data.get('meta') or {}).get('pagination') or {}).get('total')
                if (not isinstance(rows, list) or isinstance(total, bool)
                        or not isinstance(total, int) or total < 0):
                    failures += 1
                    if failures > retries:
                        raise QuakeCollectionError('缺少有效结果列表/total, 不能据此标记采集完成')
                    time.sleep(min(30, 2 ** (failures - 1)))
                    continue
                self.success_streak += 1
                if self.success_streak >= 2 and self.page_size < self.target_page_size:
                    self.page_size = min(self.target_page_size, self.page_size * 2)
                    self.success_streak = 0
                    log(f'[Quake] 网络已恢复, 后续每页回升到 {self.page_size} 条')
                return rows, total, key, payload['size'], action
            if action in ('permission', 'quota', 'token'):
                self.dead.add(key)
                self.preferred = None
                log(f'[Quake] key=#{self.keys.index(key)+1} {action}, 换 key 接续当前页')
                continue
            if action == 'rate':
                rates += 1
                self.preferred = None
                if rates >= max(10, len(self.keys) * 3):
                    raise QuakeCollectionError('持续限流, 待处理任务已保留')
                continue  # requester 已统一提高下次请求间隔
            if action in ('limit', 'param'):
                return [], 0, key, payload['size'], action
            failures += 1
            self.preferred = None
            if failures > retries:
                raise QuakeCollectionError('API 持续返回未知错误, 待处理任务已保留')
            delay = min(30, 2 ** (failures - 1))
            log(f'[Quake] 未知 API 错误, {delay}s 后重试')
            time.sleep(delay)


def _quake_node(network, port=None, exclude_ports=None):
    return {'network': str(network), 'port': port, 'exclude_ports': exclude_ports or [], 'start': 0, 'port_hints': []}


def _quake_same_task(left, right):
    return all(left[field] == right[field] for field in ('network', 'port', 'exclude_ports'))


def _quake_coalesce_tasks(tasks):
    merged = {}
    for original in tasks:
        node = dict(original)
        key = (node['network'], node['port'], tuple(node['exclude_ports']))
        if key not in merged:
            merged[key] = node
        else:
            existing = merged[key]
            existing['start'] = min(existing['start'], node['start'])
            existing['port_hints'] = list(dict.fromkeys(existing.get('port_hints', []) + node.get('port_hints', [])))[:64]
    return list(merged.values())


def _quake_record_unresolved(state, node, reason):
    for record in state['unresolved']:
        if _quake_same_task(record['node'], node):
            record['node']['start'] = min(record['node']['start'], node['start'])
            record['filtered_pages'] = record.get('filtered_pages', 1) + 1
            return
    state['unresolved'].append({'node': dict(node), 'reason': reason, 'filtered_pages': 1})


def _quake_node_query(base, node):
    query = f'({base}) AND ip:"{node["network"]}"'
    if node['port'] is not None:
        query += f' AND port:{node["port"]}'
    if node['exclude_ports']:
        query += ' AND NOT (' + ' OR '.join(f'port:{port}' for port in node['exclude_ports']) + ')'
    return query


def _quake_split_node(node, rows):
    network = ipaddress.ip_network(node['network'])
    if network.prefixlen < network.max_prefixlen:
        return [_quake_node(child, node['port'], list(node['exclude_ports'])) for child in network.subnets()]
    if node['port'] is not None:
        return []
    excluded = set(node['exclude_ports'])
    ports = []
    candidates = list(rows) + [{'port': port} for port in node.get('port_hints', [])]
    for row in candidates:
        port = row.get('port') if isinstance(row, dict) else None
        if isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= 65535 and port not in excluded and port not in ports:
            ports.append(port)
        if len(ports) >= 64:
            break
    if not ports:
        return []
    children = [_quake_node(network, port) for port in ports]
    children.append(_quake_node(network, exclude_ports=sorted(excluded | set(ports))))
    return children


def _quake_state_identity(cfg):
    versions = cfg.get('ip_versions', [4, 6])
    if not isinstance(versions, list) or not versions or any(type(v) is not int or v not in (4, 6) for v in versions):
        raise ValueError('quake ip_versions 必须是 [4]、[6] 或 [4, 6]')
    return {'query': (cfg.get('query') or cfg.get('base_query') or '').strip(),
            'url': cfg['url'], 'latest': cfg.get('latest', True),
            'window': cfg.get('window', 1000), 'ip_versions': sorted(set(versions))}


def _quake_open_state(cfg):
    identity = _quake_state_identity(cfg)
    directory = os.path.abspath(cfg.get('state_dir', 'quake_cidr_state'))
    path = os.path.join(directory, 'state.json')
    if os.path.isfile(path):
        try:
            with open(path, encoding='utf-8') as f:
                state = json.load(f)
            if (state.get('version') != 1 or state.get('identity') != identity
                    or not all(isinstance(state.get(key), list) for key in ('pending', 'unresolved', 'parts'))
                    or not isinstance(state.get('completed'), int) or not isinstance(state.get('created'), int)):
                raise ValueError('断点不匹配')
            for node in state['pending'] + [record['node'] for record in state['unresolved']]:
                network = ipaddress.ip_network(node['network'])
                if network.version not in identity['ip_versions']:
                    raise ValueError('断点 IP 版本不匹配')
                port = node['port']
                excluded = node['exclude_ports']
                if ((port is not None and (type(port) is not int or not 0 <= port <= 65535))
                        or not isinstance(excluded, list)
                        or any(type(p) is not int or not 0 <= p <= 65535 for p in excluded)):
                    raise ValueError('断点端口无效')
                if type(node['start']) is not int or node['start'] < 0:
                    raise ValueError('断点偏移无效')
            for part in state['parts']:
                relative = part['file']
                full = os.path.realpath(os.path.join(directory, relative))
                if os.path.commonpath([os.path.realpath(directory), full]) != os.path.realpath(directory) or not os.path.isfile(full):
                    raise ValueError('分片缺失或路径无效')
            # 权限不足等任务下次重新尝试; 已完成任务不会重发请求.
            tasks = state['pending'] + [record['node'] for record in state['unresolved']]
            state['pending'] = _quake_coalesce_tasks(tasks)
            state['unresolved'] = []
            return directory, path, state
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            raise ValueError('Quake 断点无法恢复; 原目录已保留, 请更换 state_dir 或备份后移走旧目录') from e
    if os.path.isdir(directory) and set(os.listdir(directory)) - {'.run.lock', 'run.json'}:
        raise ValueError('Quake 断点目录非空但缺少 state.json; 原文件已保留, 请更换 state_dir')
    os.makedirs(os.path.join(directory, 'parts'), exist_ok=True)
    roots = [_quake_node('0.0.0.0/0' if v == 4 else '::/0') for v in identity['ip_versions']]
    state = {'version': 1, 'identity': identity, 'pending': list(reversed(roots)),
             'unresolved': [], 'parts': [], 'completed': 0, 'created': len(roots), 'requests': 0}
    _atomic_write_json(path, state)
    return directory, path, state


def _search_quake_cidr(cfg):
    directory, path, state = _quake_open_state(cfg)
    base = state['identity']['query']
    window = state['identity']['window']
    if not isinstance(window, int) or isinstance(window, bool) or window <= 0:
        raise ValueError('quake window 必须是正整数')
    budget = cfg.get('max_partitions', 100000)
    client = _QuakeClient(cfg)
    results = _module_results()
    seen = {item['host'] for item in results}
    log(f'[Quake] CIDR 二分: IPv{", IPv".join(map(str, state["identity"]["ip_versions"]))}, '
        f'窗口={window}, keys={len(client.keys)}, 断点={directory}')
    log(f'[Quake] 基础语法: {base}; 已完成 {state["completed"]}, 待处理 {len(state["pending"])}')
    try:
        for part in state['parts']:
            with open(os.path.join(directory, part['file']), encoding='utf-8') as f:
                assets = json.load(f)
            if not isinstance(assets, list):
                raise ValueError('分片不是资产列表')
            for asset in assets:
                if not isinstance(asset, dict) or not isinstance(asset.get('host'), str) or not parse_url_key(asset):
                    raise ValueError('分片含无效资产')
                if asset['host'] not in seen:
                    seen.add(asset['host'])
                    results.append(asset)
    except (ValueError, TypeError, KeyError) as e:
        raise ValueError('Quake 分片损坏; 原断点已保留, 请恢复分片或更换 state_dir') from e
    log(f'[Quake] 已恢复 {len(results)} 条可用资产')
    request_baseline = state.get('requests', 0)
    mask_probes = cfg.get('masked_key_probes', 3)
    snapshot_path = os.path.join(directory, 'quake_urls.txt')
    snapshot_at = None

    def snapshot(force=False):
        nonlocal snapshot_at
        now = time.monotonic()
        if not force and snapshot_at is not None and now - snapshot_at < 15:
            return
        with _atomic_text_file(snapshot_path) as target:
            for asset in results:
                target.write(asset['host'] + '\n')
        snapshot_at = now

    snapshot(force=True)
    log(f'[Quake] 实时结果文件: {snapshot_path} (每15秒或结束时更新, 当前 {len(results)} 条)')

    def save():
        state['requests'] = request_baseline + client.requests
        _atomic_write_json(path, state)

    def store(assets):
        if not assets:
            return
        relative = f'parts/{len(state["parts"]):08d}.json'
        _atomic_write_json(os.path.join(directory, relative), assets)
        state['parts'].append({'file': relative, 'rows': len(assets)})

    def defer(node, reason):
        # 重试时从当前页继续, 窗口超限在下次可重新划分.
        _quake_record_unresolved(state, node, reason)
        state['pending'].pop()
        log(f'[Quake] [!] {node["network"]} 未完整: {reason}; 已记录待恢复')
        save()

    def split(node, rows):
        children = _quake_split_node(node, rows)
        if not children:
            defer(node, '单 IP/单端口仍超限或缺少可细分端口')
            return
        if state['created'] + len(children) > budget:
            defer(node, '达到 max_partitions 任务数量上限')
            return
        state['unresolved'] = [record for record in state['unresolved'] if not _quake_same_task(record['node'], node)]
        state['pending'].pop()
        # 新子网排在队列尾, 先让其他待处理范围获得机会. 栈尾为下一任务.
        state['pending'][0:0] = list(reversed(children))
        state['created'] += len(children)
        log(f'[Quake] {node["network"]} 超过窗口, '
            f'{"CIDR 二分" if len(children) == 2 and children[0]["network"] != node["network"] else "端口细分+尾分区"}, '
            f'待处理 {len(state["pending"])} 项')
        save()

    try:
        while state['pending']:
            node = state['pending'][-1]
            query = _quake_node_query(base, node)
            masked_keys = set()
            page_rows = []
            first_page_limits = 0
            if not cfg.get('full_keys') and 'mask_next_index' in node:
                client.cursor = node['mask_next_index']
            while True:
                start = node['start']
                if start >= window:
                    split(node, page_rows)
                    break
                rows, total, key, requested, action = client.fetch(
                    query, start, min(cfg.get('pageSize', 500), window - start),
                    f'CIDR {node["network"]} 已完成{state["completed"]}/待处理{len(state["pending"])}', masked_keys)
                if action == 'param':
                    defer(node, '接口拒绝该网段/查询语法; 未将其作为空结果')
                    break
                if action == 'limit':
                    if start == 0 and not page_rows:
                        first_page_limits += 1
                        if client.page_size > 1 and first_page_limits <= cfg.get('retries', 5):
                            client.page_size = max(1, client.page_size // 2)
                            client.target_page_size = min(client.target_page_size, client.page_size)
                            client.min_page_size = min(client.min_page_size, client.page_size)
                            log(f'[Quake] 首屏受限且未取得 total, 减小为每页 {client.page_size} 条后重试, 不盲目二分')
                            continue
                        defer(node, '首屏持续受限且无法取得 total; 无法判断是条数限制还是查询权限')
                        break
                    if start > 0:
                        window = min(window, start)
                    split(node, page_rows)
                    break
                page_rows.extend(rows)
                hints = node.setdefault('port_hints', [])
                for row in rows:
                    port = row.get('port') if isinstance(row, dict) else None
                    if type(port) is int and 0 <= port <= 65535 and port not in hints and len(hints) < 64:
                        hints.append(port)
                # 只保存本轮尚未存过的规范化资产, 不重复落盘父子网的同一结果.
                before = len(results)
                counts = _quake_ingest(rows, results, seen)
                store(results[before:])
                log(f'[Quake] {node["network"]} start={start} total={total}: 收到 {len(rows)}, '
                    f'新增 {counts["added"]}, 掩码 {counts["masked"]}, 无效 {counts["invalid"]}, 重复 {counts["duplicate"]}; '
                    f'累计请求 {request_baseline + client.requests}, 可用资产 {len(results)}')
                save()
                snapshot()
                # 内部节点只需要 total; 掩码权限不影响判定是否应二分.
                if total > window:
                    split(node, page_rows)
                    break
                if rows and counts['masked'] == len(rows):
                    masked_keys.add(key)
                    candidates = set(client.keys) - client.dead - masked_keys
                    if candidates and len(masked_keys) < mask_probes:
                        index = client.keys.index(key) + 1
                        ordered = client.keys[index:] + client.keys[:index]
                        client.preferred = next(k for k in ordered if k in candidates)
                        log(f'[Quake] 本页全掩码, 同页换 key 探测 ({len(masked_keys)}/{mask_probes}次上限)')
                        continue
                    client.preferred = None
                    node['mask_next_index'] = (client.keys.index(key) + 1) % len(client.keys)
                    log(f'[Quake] 本页掩码探测结束 (已试{len(masked_keys)}个key, 其余未判定无效); '
                        '记录待补采并继续其他任务, 需要时可提高 masked_key_probes 或补充 full_keys')
                else:
                    client.preferred = key
                if counts['masked'] or counts['invalid']:
                    _quake_record_unresolved(state, node, '部分记录掩码或无效')
                node['start'] = start + len(rows)
                if node['start'] >= total:
                    state['pending'].pop()
                    filtered = any(_quake_same_task(record['node'], node) for record in state['unresolved'])
                    if not filtered:
                        state['completed'] += 1
                    save()
                    log(f'[Quake] {node["network"]} {"翻页结束, 过滤记录待补采" if filtered else "完成"}, 共 {node["start"]}/{total} 条')
                    break
                if not rows:
                    defer(node, '未到 total 即返回空页, 不能确认完整')
                    break
                # 短页不等于末页: total 仍有剩余时继续, 防止服务端静默缩小 pageSize.
                # 每页轮换任务, 防止一个慢网段长期挡住其他范围.
                state['pending'].insert(0, state['pending'].pop())
                save()
                break
    except QuakeCollectionError as e:
        log(f'[Quake] [!] {e}')
        save()
    except KeyboardInterrupt:
        save()
        snapshot(force=True)
        log('[Quake] 已保存当前页偏移、待处理网段及已收结果, 下次从断点恢复')
        raise
    snapshot(force=True)
    log(f'[Quake] CIDR 结束: 可用资产 {len(results)}, 已完成 {state["completed"]}, '
        f'待处理 {len(state["pending"])}, 未完整 {len(state["unresolved"])}; 断点保留')
    if not state['pending'] and not state['unresolved']:
        log('[Quake] 本轮范围内的任务全部完成')
    return results


@register_handler('quake')
def search_quake(cfg):
    if cfg.get('cidr', True) and cfg.get('all', True):
        return _managed_engine("quake", cfg, _search_quake_cidr)
    return _search_quake_partitioned(cfg)


# ---- 合并 & 去重 ----

def _default_port(scheme):
    return 443 if scheme == "https" else 80


def parse_url_key(asset):
    raw = (asset.get("host") or asset.get("url") or "").strip()
    if not raw:
        return None

    if "://" not in raw:
        # 未加方括号的 IPv6 地址 (含多个冒号) 需要加方括号, 否则 urlparse 解析端口会报错
        if raw.count(":") >= 2 and not raw.startswith("["):
            raw = f"[{raw}]"
        port_val = asset.get("port")
        if port_val not in (None, ""):
            raw = f"http://{raw}" if not raw.startswith(":") else "http" + raw
        else:
            raw = "http://" + raw

    try:
        p = urllib.parse.urlparse(raw)
    except Exception:
        return None

    scheme = (asset.get("scheme") or p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    if not host:
        return None

    try:
        port = p.port
    except ValueError:
        return None  # 异常 IPv6 等无法解析端口, 跳过
    if not port:
        port_val = asset.get("port")
        if port_val is not None and str(port_val).strip():
            try:
                port = int(port_val)
            except (ValueError, TypeError):
                port = _default_port(scheme)
        else:
            port = _default_port(scheme)

    if not 1 <= int(port) <= 65535:
        return None
    return scheme, host, int(port)


def merge_and_dedup(*result_lists):
    seen = {}
    order = []

    for results in result_lists:
        for r in results:
            # 丢弃掩码 IP 的结果 (120.*.*.*)
            if _is_masked_ip(r.get("ip")) or "*" in str(r.get("host") or ""):
                continue
            key = parse_url_key(r)
            if not key:
                continue
            if key not in seen:
                seen[key] = {
                    "scheme":   key[0],
                    "host":     key[1],
                    "port":     key[2],
                    "ip":       r.get("ip") or "",
                    "protocol": r.get("protocol") or "",
                    "title":    r.get("title") or "",
                    "sources":  {r["source"]},
                }
                order.append(key)
            else:
                seen[key]["sources"].add(r["source"])
                if not seen[key]["ip"] and r.get("ip"):
                    seen[key]["ip"] = r["ip"]
                if not seen[key]["title"] and r.get("title"):
                    seen[key]["title"] = r["title"]

    return [seen[k] for k in order]


def format_url(item):
    host = item["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{item['scheme']}://{host}:{item['port']}"


# ---- 主流程 ----

def _load_previous_urls(output_file):
    """读取已有的输出文件 (纯 URL 行), 转成 merge_and_dedup 可用的结果结构. 空/不存在返回 []."""
    if not os.path.exists(output_file):
        return []
    results = []
    with open(output_file, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "*" in s:
                continue  # 丢弃历史掩码 IP 结果
            key = parse_url_key({"url": s})
            if not key:
                continue
            results.append({
                "scheme":  key[0],
                "host":    key[1],
                "port":    key[2],
                "ip":      "",
                "protocol": "",
                "title":   "",
                "source":  "history",
            })
    return results


def _write_output(merged, output_file, log_file, all_results, modules):
    """把当前合并结果写入输出文件和日志文件 (覆盖写). 空结果时返回 False 不落盘."""
    if not merged:
        return False

    with _atomic_text_file(output_file) as f:
        for m in merged:
            f.write(format_url(m) + "\n")

    with _atomic_text_file(log_file) as f:
        f.write(f"# 合并时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        for name in all_results:
            cfg = modules.get(name, {})
            f.write(f"# {name} 语法: {cfg.get('query', '?')}\n")
        f.write(f"# 去重后总数: {len(merged)}\n")
        f.write(f"# 列: url \t sources \t ip \t title\n\n")
        for m in merged:
            sources = ",".join(sorted(m["sources"]))
            f.write(f"{format_url(m)}\t{sources}\t{m.get('ip', '')}\t{m.get('title', '')}\n")
    return True


def _select_modules(modules, sources):
    """解析 all、逗号分隔字符串或列表, 保持配置中的执行顺序."""
    if isinstance(sources, str):
        sources = [sources]
    if not isinstance(sources, (list, tuple)) or not sources:
        raise ValueError("sources 应为 all 或 fofa、hunter、quake 的组合")
    if not isinstance(modules, dict) or any(not isinstance(value, str) for value in sources):
        raise ValueError("module 必须是对象, sources 必须是来源名称或名称列表")
    selected = {part.strip().lower() for value in sources for part in value.split(",")}
    allowed = {"fofa", "hunter", "quake"}
    if selected == {"all"}:
        return dict(modules)
    if not selected or not selected <= allowed:
        raise ValueError("sources 只支持 all 或 fofa、hunter、quake; all 不能与其他来源混用")
    missing = selected - modules.keys()
    if missing:
        raise ValueError("所选来源缺少配置: " + ", ".join(sorted(missing)))
    return {name: cfg for name, cfg in modules.items() if name in selected}


def _run_collect(config, output_file=None, log_file=None, sources=None):
    """
    执行采集流程, 返回合并去重后的资产列表.
    config: JSON 配置 dict
    output_file: 覆盖配置中的 output 路径
    log_file: 覆盖配置中的 logfile 路径
    sources: all 或来源名称组合; None 时读取配置 sources (默认 all)
    """
    global _CURRENT_MODULE

    modules = _select_modules(config.get("module", {}),
                              sources if sources is not None else config.get("sources", "all"))
    if not modules:
        log("[!] 配置中没有 module 定义")
        return []

    output_file = output_file or config.get("output", "collect_result.txt")
    log_file    = log_file or config.get("logfile", "collect_result.log")

    if os.path.realpath(output_file) == os.path.realpath(log_file):
        raise ValueError("output 和 logfile 不能指向同一个文件")
    for name, cfg in modules.items():
        if name not in MODULE_HANDLERS:
            continue
        if not isinstance(cfg, dict):
            raise ValueError(f"{name} 配置必须是对象")
        query = cfg.get("query") or cfg.get("base_query")
        if not isinstance(query, str) or not query.strip():
            raise ValueError(f"{name} query 不能为空")
        if not cfg.get("url"):
            raise ValueError(f"{name} 缺少 url")
        for field in ("size", "pageSize"):
            value = cfg.get(field, 1000 if field == "size" else 100)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} {field} 必须是正整数")
        if name == "quake":
            for field, default in (("window", 1000), ("max_partitions", 100000), ("min_page_size", 50), ("masked_key_probes", 3)):
                value = cfg.get(field, default)
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise ValueError(f"quake {field} 必须是正整数")
        timeout = cfg.get("timeout", 30)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout < float("inf"):
            raise ValueError(f"{name} timeout 必须是正数")
        for field, default in (("interval", 0), ("retries", 5)):
            value = cfg.get(field, default)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not 0 <= value < float("inf")
                    or (field == "retries" and not isinstance(value, int))):
                raise ValueError(f"{name} {field} 必须是非负数, retries 必须是整数")
        if name == "fofa" and (not cfg.get("email") or not cfg.get("token")):
            raise ValueError("fofa 缺少 email 或 token")

    # 历史文件只加载一次, 避免每完成一个模块都重新解析全部 URL.
    previous_urls = _load_previous_urls(output_file)

    log("=" * 70)
    log(f"[*] 采集开始: {datetime.now():%Y-%m-%d %H:%M:%S}")
    log(f"[*] 输出: {output_file}  日志: {log_file}")
    log(f"[*] 启用模块: {', '.join(modules.keys())}")
    log("=" * 70)

    all_results = {}
    merged = []

    def _save_now():
        # 当前所有模块结果 + 历史已采集 URL 并集, 只增不减
        result_lists = [r for r in all_results.values() if r]
        if previous_urls:
            result_lists.append(previous_urls)
        return merge_and_dedup(*result_lists)

    for name, cfg in modules.items():
        handler = MODULE_HANDLERS.get(name)
        if not handler:
            log(f"\n[!] 未知模块: {name}, 跳过")
            continue

        log(f"\n=== {name.upper()} ===")
        t0 = time.time()
        _CURRENT_MODULE = name
        partial = []
        COLLECT_SINK[name] = partial  # 兼容诊断用快照, 不再作为跨调用的数据路由
        token = _ACTIVE_RESULTS.set(partial)
        try:
            res = handler(cfg)
        except KeyboardInterrupt:
            # 抢救当前模块已采集的部分数据
            res = partial
            all_results[name] = res
            log(f"\n[!] {name} 被中断, 已保留 {len(res)} 条部分数据")
            merged = _save_now()
            if _write_output(merged, output_file, log_file, all_results, modules):
                log(f"[!] 已抢救保存 {len(merged)} 条 -> {output_file}")
            else:
                log("[!] 中断时无数据可保存")
            return merged
        except Exception as e:
            log(f"[{name}] 采集异常: {e}")
            res = partial
        finally:
            _ACTIVE_RESULTS.reset(token)
            _CURRENT_MODULE = None
        all_results[name] = res
        log(f"[{name}] 共 {len(res)} 条, 用时 {time.time() - t0:.1f}s")

        # 每完成一个模块就落盘一次, 中途中断也不丢已完成数据
        merged = _save_now()
        if _write_output(merged, output_file, log_file, all_results, modules):
            log(f"[*] 已保存 {len(merged)} 条 -> {output_file}")

    # 最终汇总
    log("\n=== 合并去重 ===")
    old_urls = previous_urls
    log("各模块原始数量:")
    for name, res in all_results.items():
        log(f"  {name:8s} {len(res)}")
    if old_urls:
        log(f"  历史目标:    {len(old_urls)}")
    log(f"去重后:       {len(merged)}")

    if not merged:
        log("[!] 合并结果为空 (所有来源可能都失败), 不覆盖已有文件")
        return []

    log(f"\n[+] 主结果 -> {output_file} ({len(merged)} 条)")
    log(f"[+] 详细日志 -> {log_file}")
    return merged


def run_collect(config, output_file=None, log_file=None, sources=None, new_run=False, resume_dir=None, query=None):
    """共享入口: 来源选择、任务控制和输出互斥; 引擎配置仅复制、不写回凭据文件."""
    modules = _select_modules(config.get("module", {}),
                              sources if sources is not None else config.get("sources", "all"))
    if (resume_dir or query is not None) and len(modules) != 1:
        raise ValueError("--resume / --query 需要用 -s 明确指定一个来源")
    if new_run and resume_dir:
        raise ValueError("--new 与 --resume 不能同时使用")
    if resume_dir and (next(iter(modules), None) not in ("fofa", "quake")):
        raise ValueError("Hunter 暂无可显式恢复的 CIDR 任务")
    selected = {}
    for name, cfg in modules.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"{name} 配置必须是对象")
        cfg = dict(cfg)
        if name == "fofa" and not cfg.get("url"):
            cfg["url"] = FOFA_DEFAULT_URL
        if query is not None:
            cfg["query"] = query
        if name in ("fofa", "quake"):
            if new_run:
                cfg["new_run"] = True
            if resume_dir:
                if name == "quake" and (not cfg.get("cidr", True) or not cfg.get("all", True)):
                    raise ValueError("--resume 需要 Quake CIDR 全量模式")
                cfg["resume_dir"] = resume_dir
        selected[name] = cfg
    output = output_file or config.get("output", "collect_result.txt")
    logfile = log_file or config.get("logfile", "collect_result.log")
    paths = sorted({os.path.realpath(output), os.path.realpath(logfile)})
    if len(paths) != 2:
        raise ValueError("output 和 logfile 不能指向同一个文件")
    with ExitStack() as held:
        for path in paths:
            held.enter_context(exclusive_lock(path + '.lock'))
        return _run_collect(dict(config, module=selected), output, logfile, sources="all")


DEFAULT_CONFIG_TEMPLATE = json.dumps({
    "sources": "all",
    "output": "assets.txt",
    "logfile": "assets.log",
    "module": {
        "fofa": {
            "url": "https://fofa.info/api/v1/search/all",
            "email": "请填写你的FOFA邮箱",
            "token": "请填写你的FOFA API Token",
            "full": False,
            "interval": 0.5,
            "retries": 5,
            "state_dir": "fofa_cidr_state",
            "query": 'icon_hash=="-1200473251" || title="hermes studio"',
        },
        "hunter": {
            "url": "https://hunter.qianxin.com/openApi/search",
            "keys": ["请填写你的Hunter API Key"],
            "all": True,
            "size": 1000,
            "pageSize": 100,
            "query": 'web.title="hermes studio"||web.icon=="6802d0a3b79fe23178a930507eee2a6d"',
        },
        "quake": {
            "url": "https://quake.360.net/api/v3/search/quake_service",
            "keys": ["请填写你的Quake API Key"],
            "all": True,
            "size": 1000,
            "pageSize": 500,
            "latest": True,
            "interval": 3,
            "cidr": True,
            "state_dir": "quake_cidr_state",
            "ip_versions": [4, 6],
            "adaptive": True,
            "query": 'title: "hermes studio"',
        },
    },
}, indent=2, ensure_ascii=False)


def ensure_config(config_path):
    """检查配置文件是否存在, 不存在则自动生成默认模板"""
    if os.path.exists(config_path):
        return True

    print(f"[*] 配置文件不存在: {config_path}")
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(DEFAULT_CONFIG_TEMPLATE)
        print(f"[+] 已生成默认配置文件: {config_path}")
        print("    请编辑该文件, 填入各引擎的 API 凭据后再运行")
    except Exception as e:
        print(f"[!] 无法创建配置文件: {e}")
        return False
    return False


def main():
    import argparse
    ap = argparse.ArgumentParser(description="FOFA + Hunter + Quake 网络空间测绘资产采集")
    ap.add_argument("-c", "--config", default="config.json", help="配置文件路径 (默认: config.json)")
    ap.add_argument("-o", "--output", default=None, help="输出文件路径 (覆盖配置)")
    ap.add_argument("-l", "--logfile", default=None, help="日志文件路径 (覆盖配置)")
    ap.add_argument("-s", "--sources", "--source", nargs="+", default=None,
                    help="采集来源, 默认 all; 示例: -s fofa 或 -s fofa hunter 或 -s fofa,quake")
    ap.add_argument("-q", "--query", default=None, help="临时覆盖所选单一来源的查询语法")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--new", action="store_true", help="新建任务, 不自动续采旧任务")
    mode.add_argument("--resume", default=None, help="恢复指定运行目录, 需 -s 指定单一来源")
    args = ap.parse_args()

    if not ensure_config(args.config):
        return 1

    try:
        config = load_config(args.config)
        options = {}
        if args.new:
            options["new_run"] = True
        if args.resume:
            options["resume_dir"] = args.resume
        if args.query is not None:
            options["query"] = args.query
        result = run_collect(config, output_file=args.output, log_file=args.logfile, sources=args.sources, **options)
    except (ValueError, OSError) as e:
        log(f"[!] 配置或文件错误: {e}")
        return 1
    except KeyboardInterrupt:
        log("\n[!] 被用户中断")
        return 130
    if not result:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
