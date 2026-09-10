#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
space_search_collector.py — FOFA + Hunter + Quake 网络空间测绘资产采集 (独立脚本 + 可被 pipeline 引用)

用法:
  python3 space_search_collector.py                        # 使用默认配置 config.json
  python3 space_search_collector.py -c my_config.json      # 指定配置文件
  python3 space_search_collector.py -o output.txt          # 指定输出文件
  python3 space_search_collector.py -l output.log          # 指定日志文件

配置文件格式 (config.json):
  {
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
  中断/额度耗尽后下次以相同 query 运行会自动从断点恢复; 全部完成后自动清理断点目录。

作为模块引用:
  from space_search_collector import load_config, run_collect
  config = load_config("config.json")
  results = run_collect(config)  # 返回合并去重后的资产列表
"""

import base64
import csv
import json
import os
import random
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from threading import Lock

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/150.0.0.0 Safari/537.36")

TIMEOUT = 60
PRINT_LOCK = Lock()

# 运行期共享结果槽: 各模块采集过程中实时写入, 供中断时抢救部分数据
COLLECT_SINK = {}
_CURRENT_MODULE = None


def _module_results():
    """返回当前模块的结果列表 (共享引用). 独立调用时返回普通空列表."""
    if _CURRENT_MODULE is None:
        return []
    return COLLECT_SINK.setdefault(_CURRENT_MODULE, [])


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

def http_get(url, params=None, headers=None, timeout=TIMEOUT):
    if params:
        url = url + "?" + urllib.parse.urlencode(params, doseq=True)
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
        return -1, str(e)


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
        return -1, str(e)


# ---- 通用工具 ----

def _is_masked_ip(ip):
    """IP 被平台掩码 (如 120.*.*.*) 时返回 True."""
    return "*" in str(ip or "")


def _resolve_keys(cfg):
    """读取 keys 列表, 兼容旧的单 key 配置."""
    keys = cfg.get("keys")
    if keys is None and "key" in cfg:
        keys = [cfg["key"]]
    return [k for k in (keys or []) if k]


def _atomic_write_json(path, data):
    """原子写入 JSON, 避免中断留下半个文件."""
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, path)


# ---- FOFA (CIDR 二分全量采集) ----

FOFA_FIELDS = "host,ip,port,protocol,title,country,region,city,domain,link"
FOFA_LIMIT = 10_000  # FOFA 单次查询返回上限
FOFA_STATE_FILENAME = "state.json"
FOFA_PARTS_DIRNAME = "parts"
FOFA_PART_FIELDS = ["link", "host", "ip", "port", "protocol",
                    "title", "country", "region", "city", "domain"]


def _fofa_parse_row(row):
    """解析 FOFA 单行结果 -> dict."""
    row = (list(row) + [None] * 10)[:10]
    host, ip, port, protocol, title, country, region, city, domain, link = row
    return {
        "host":     host or "",
        "ip":       str(ip or ""),
        "port":     port,
        "protocol": (protocol or "").lower(),
        "title":    title or "",
        "country":  country or "",
        "region":   region or "",
        "city":     city or "",
        "domain":   domain or "",
        "link":     link or "",
    }


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
    """FOFA 单次请求, 返回 (rows, total, errmsg)."""
    params = {
        "qbase64": base64.b64encode(query.encode("utf-8")).decode("utf-8"),
        "email":   cfg["email"],
        "key":     cfg["token"],
        "page":    page,
        "size":    min(size, FOFA_LIMIT),
        "full":    "true" if full else "false",
        "fields":  FOFA_FIELDS,
    }
    code, text = http_get(cfg["url"], params=params)
    if code != 200:
        return [], 0, f"HTTP {code}: {text[:150]}"
    try:
        data = json.loads(text)
    except Exception:
        return [], 0, "JSON 解析失败"
    if data.get("error"):
        return [], 0, data.get("errmsg", "?")
    rows = []
    for row in (data.get("results") or []):
        p = _fofa_parse_row(row)
        if p:
            rows.append(p)
    return rows, data.get("size", 0), None


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


def _fofa_load_state(state_dir, base_query):
    """加载同查询的断点状态; 不存在/损坏/查询不匹配时清理旧断点并返回 None."""
    state_path = os.path.join(state_dir, FOFA_STATE_FILENAME)
    if not os.path.isfile(state_path):
        return None
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        if state.get("base_query") == base_query and state.get("pending") is not None:
            return state
    except Exception:
        pass
    shutil.rmtree(state_dir, ignore_errors=True)
    return None


def _fofa_save_part(state_dir, cidr, rows):
    """网段数据落盘为分片 CSV (原子写), 返回相对路径."""
    name = cidr.replace(".", "_").replace("/", "_") + ".csv"
    rel_path = os.path.join(FOFA_PARTS_DIRNAME, name)
    path = os.path.join(state_dir, rel_path)
    temp_path = path + ".tmp"
    with open(temp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FOFA_PART_FIELDS)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in FOFA_PART_FIELDS})
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, path)
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


@register_handler("fofa")
def search_fofa(cfg):
    """
    FOFA CIDR 二分全量采集, 突破单次 10000 条上限:
      从 0.0.0.0/0 开始, 每个网段只查一次 total:
        total == 0          -> 跳过
        0 < total <= 10000  -> 收取返回数据, 存分片 CSV
        total > 10000       -> 二分网段, 继续深入
    支持断点续采: 每个网段处理完即落盘 state.json, 中断后同查询自动恢复;
    全部完成后自动清理断点目录。
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

    state = _fofa_load_state(state_dir, base)
    if state is not None:
        log(f"[FOFA] 恢复断点: 已完成 {len(state['completed'])} 个网段, "
            f"累计 {state['requests']} 次请求")
        # 已完成网段的数据从分片 CSV 读回, 不重复消耗 API
        for rec in state["completed"]:
            if rec.get("status") != "saved":
                continue
            path = os.path.join(state_dir, rec.get("file", ""))
            if not os.path.isfile(path):
                continue
            with open(path, "r", newline="", encoding="utf-8") as f:
                _fofa_ingest(csv.DictReader(f), results, seen)
        log(f"[FOFA] 断点数据载入: {len(results)} 条")
    else:
        state = {"base_query": base, "pending": [[0, 0]], "completed": [], "requests": 0}
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
            part = _fofa_save_part(state_dir, cidr, rows)
            added = _fofa_ingest(rows, results, seen)
            state["completed"].append({
                "cidr": cidr, "total": total, "rows": len(rows),
                "file": part, "status": "saved",
            })
            log(f"[FOFA] {cidr}: {total} 条, 新增 {added} "
                f"(已扫 {len(state['completed'])} 段, 累计 {len(results)} 条)")
        elif prefix_length == 32:
            state["completed"].append({
                "cidr": cidr, "total": total, "rows": len(rows), "status": "cannot_split",
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

    # 全部完成, 清理断点目录 (数据已进入主输出, 分片无需保留)
    shutil.rmtree(state_dir, ignore_errors=True)
    log(f"[FOFA] CIDR 采集完成: {len(results)} 条, 共 {state['requests']} 次请求, 断点目录已清理")
    return results


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

    while next_page <= max_pages and not stop and consecutive_fail < 10:
        api_key = keys[key_idx % len(keys)]
        key_idx += 1

        page, code, text, data, used_key = _hunter_page(next_page, api_key)
        key_short = used_key[:16] + "..."

        if code != 200 or not data:
            log(f"[Hunter] page={page} HTTP {code} key={key_short}")
            consecutive_fail += 1
            time.sleep(1)
            continue

        api_code = data.get("code")
        if api_code == 40204:
            log(f"[Hunter] page={page} key={key_short} 积分用完, 换 key")
            continue

        if api_code != 200:
            msg = data.get("message", "")
            if any(kw in msg.lower() for kw in ("请求太多", "太多啦")):
                log(f"[Hunter] page={page} 限流, 等待 3s")
                time.sleep(3)
                continue
            log(f"[Hunter] page={page} API code={api_code} msg={msg}")
            consecutive_fail += 1
            continue

        payload = data.get("data") or {}
        arr = payload.get("arr") or []
        total = payload.get("total", 0)
        page_assets = 0
        for asset in arr:
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
    # 翻页/条数上限 (基础会员最多翻到第1000条) -> 全局限制, 换 key 也没用, 应停止
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
    if code_s == "q2003":
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
            q = base
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


def _quake_fetch_page(url, api_key, query, start, page_size, latest):
    """单次请求 Quake, 返回解析后的 JSON dict, 失败返回 None."""
    payload = {"query": query, "start": start, "size": page_size,
               "ignore_cache": False, "latest": latest}
    code, text = http_post_json(url, payload, headers={"X-QuakeToken": api_key})
    if code != 200:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _adaptive_quake_queries(cfg, url, keys, latest, page_size):
    """采样 + 分析分布(国家/省份/端口) + 生成子查询 (含 NOT 反选尾覆盖长尾)."""
    from collections import Counter

    base = cfg["query"]
    sample = []
    base_total = 0

    # 采样: 取前 2 页 (每页 page_size, 共 up to 1000 条)
    for start in (0, page_size):
        data = _quake_fetch_page(url, keys[0], base, start, page_size, latest)
        if not data or data.get("code") != 0:
            break
        rows = data.get("data") or []
        sample.extend(_quake_parse_item(r) for r in rows)
        base_total = (data.get("meta") or {}).get("pagination", {}).get("total", base_total)
        if len(rows) < page_size:
            break

    if not sample:
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
        else:
            port_counter = Counter(it["port"] for it in sample
                                   if it["country"] == country and it["port"] is not None)
            for p in port_counter:
                queries.append(f'{base} && country:"{country}" && port:{p}')

    # NOT 反选尾: 排除采样覆盖的所有国家, 抓长尾国家 + 无国家字段的结果
    if country_counter:
        not_clause = " || ".join(f'country:"{c}"' for c in country_counter)
        queries.append(f'{base} && NOT ({not_clause})')

    return queries


@register_handler("quake")
def search_quake(cfg):
    """
    Quake (360 空间测绘) 搜索, 支持分区/自适应采样 + NOT 反选, 自动丢弃掩码 IP.
    配置字段: url, keys(多 key 轮巡), full_keys(实名 key, 查中国资产完整 IP),
              query(基础语法), adaptive(采样分析), partition(固定分区),
              all, size, pageSize, latest, interval
    认证: 请求头 X-QuakeToken, POST JSON body {query, start, size, latest}
    注意: 基础会员只能查最新数据 (latest=true), 每个子查询最多翻到第1000条, 限流较严.
    """
    query     = cfg.get("query") or cfg.get("base_query") or ""
    size      = cfg.get("size", 1000)      # 每个子查询最多采集条数 (API 上限 1000)
    page_size = cfg.get("pageSize", 500)   # 单次最多 500
    latest    = cfg.get("latest", True)    # 基础会员仅支持最新数据, 默认 true
    interval  = cfg.get("interval", 3)     # 每次请求间隔(秒), 降低限流风险
    keys      = _resolve_keys(cfg)

    if not keys:
        log("[Quake] [!] 未配置 key 或 keys, 跳过")
        return []

    # 实名 key (返回完整 IP): 中国资产用普通 key 会被掩码, 需用实名 key 查询
    full_keys = cfg.get("full_keys") or []
    if full_keys:
        log(f"[Quake] 实名 key (完整IP) {len(full_keys)} 个")

    # 子查询: 优先 adaptive 采样分析; 否则用 partition; 都没有则单查询
    if cfg.get("adaptive"):
        sub_queries = _adaptive_quake_queries(cfg, cfg["url"], keys, latest, page_size)
    else:
        sub_queries = _build_quake_queries(cfg)
    if not sub_queries:
        log("[Quake] [!] 无有效查询, 跳过")
        return []

    log(f"[Quake] 基础语法: {query}")
    log(f"[Quake] 子查询 {len(sub_queries)} 个, size={size}/子查询, pageSize={page_size}, latest={latest}, interval={interval}s, keys={len(keys)}")

    results = _module_results()
    seen = set()
    dead = set()        # 已失效的 key (token 错误 / 额度用完)
    rate_sleep = 1
    retry_count = 0
    key_idx = 0         # 轮巡指针, 每次请求换下一个可用 key, 摊薄限流与积分

    for qi, query in enumerate(sub_queries):
        start = 0
        total = None
        # 中国资产子查询 -> 用实名 key (未实名 key 返回掩码 IP)
        key_pool = full_keys if (full_keys and 'country:"中国"' in query) else keys

        while True:
            available = [k for k in key_pool if k not in dead]
            if not available:
                log("[Quake] [!] 所有 key 均已失效或额度用完, 停止")
                return results

            api_key = available[key_idx % len(available)]
            key_short = api_key[:16] + "..."

            payload = {
                "query":        query,
                "start":        start,
                "size":         page_size,
                "ignore_cache": False,
                "latest":       latest,
            }
            code, text = http_post_json(cfg["url"], payload, headers={"X-QuakeToken": api_key})

            if code != 200:
                log(f"[Quake] 子查询{qi+1} start={start} key={key_short} HTTP {code}: {text[:200]}")
                if code in (401, 403):
                    log(f"[Quake] key={key_short} 认证失败, 弃用该 key")
                    dead.add(api_key)
                    retry_count = 0
                    continue
                retry_count += 1
                time.sleep(1)
                if retry_count >= 5:
                    log(f"[Quake] key={key_short} HTTP 连续失败, 弃用")
                    dead.add(api_key)
                    retry_count = 0
                continue

            try:
                data = json.loads(text)
            except Exception:
                log(f"[Quake] start={start} key={key_short} JSON 解析失败: {text[:200]}")
                retry_count += 1
                if retry_count >= 5:
                    log(f"[Quake] key={key_short} 响应异常, 弃用")
                    dead.add(api_key)
                    retry_count = 0
                continue

            api_code = data.get("code")
            msg = data.get("message", "")
            if api_code != 0 and str(api_code) != "0":
                action = _quake_error_action(api_code, msg)
                if action == "limit":
                    log(f"[Quake] 子查询{qi+1} 已达会员翻页上限(前1000条) (code={api_code}), 换下一子查询")
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
                    log(f"[Quake] key={key_short} 请求过于频繁 (code={api_code}), 换下一个 key")
                    key_idx += 1
                    time.sleep(min(rate_sleep, 3))
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

            rate_sleep = 1
            retry_count = 0
            key_idx += 1   # 成功一次就轮巡到下一个 key

            rows = data.get("data") or []
            meta = data.get("meta") or {}
            pagination = meta.get("pagination") or {}
            total = pagination.get("total", 0)

            page_assets = 0
            for item in rows:
                p = _quake_parse_item(item)

                # 丢弃掩码 IP (120.*.*.*) 的结果
                if _is_masked_ip(p["ip"]):
                    continue
                if (not p["hostname"]) and (not p["ip"]):
                    continue
                if p["port"] is None:
                    continue

                url = _quake_build_url(p)

                if url not in seen:
                    seen.add(url)
                    results.append({
                        "host":     url,
                        "ip":       p["ip"],
                        "port":     p["port"],
                        "protocol": p["scheme"],
                        "title":    p["title"],
                        "source":   "quake",
                    })
                    page_assets += 1

            log(f"[Quake] 子查询{qi+1}/{len(sub_queries)} start={start} key={key_short} 新增 {page_assets} 条 (本子查询累计 {start + len(rows)}, total={total}, 全局累计 {len(results)})")

            start += len(rows)

            if not rows:
                break
            if total and start >= total:
                break
            if len(rows) < page_size:
                break
            if start >= size:
                break

            # 请求间隔, 避免基础会员限流 (q3005)
            if interval > 0:
                time.sleep(interval)

    return results


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

    scheme = (p.scheme or "http").lower()
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

    with open(output_file, "w", encoding="utf-8") as f:
        for m in merged:
            f.write(format_url(m) + "\n")

    with open(log_file, "w", encoding="utf-8") as f:
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


def run_collect(config, output_file=None, log_file=None):
    """
    执行采集流程, 返回合并去重后的资产列表.
    config: JSON 配置 dict
    output_file: 覆盖配置中的 output 路径
    log_file: 覆盖配置中的 logfile 路径
    """
    global _CURRENT_MODULE

    modules = config.get("module", {})
    if not modules:
        log("[!] 配置中没有 module 定义")
        return []

    output_file = output_file or config.get("output", "collect_result.txt")
    log_file    = log_file or config.get("logfile", "collect_result.log")

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
        old_urls = _load_previous_urls(output_file)
        if old_urls:
            result_lists.append(old_urls)
        return merge_and_dedup(*result_lists)

    for name, cfg in modules.items():
        handler = MODULE_HANDLERS.get(name)
        if not handler:
            log(f"\n[!] 未知模块: {name}, 跳过")
            continue

        log(f"\n=== {name.upper()} ===")
        t0 = time.time()
        _CURRENT_MODULE = name
        COLLECT_SINK[name] = []
        try:
            res = handler(cfg)
        except KeyboardInterrupt:
            # 抢救当前模块已采集的部分数据
            res = COLLECT_SINK.get(name, [])
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
            res = COLLECT_SINK.get(name, [])
        finally:
            _CURRENT_MODULE = None
        all_results[name] = res
        log(f"[{name}] 共 {len(res)} 条, 用时 {time.time() - t0:.1f}s")

        # 每完成一个模块就落盘一次, 中途中断也不丢已完成数据
        merged = _save_now()
        if _write_output(merged, output_file, log_file, all_results, modules):
            log(f"[*] 已保存 {len(merged)} 条 -> {output_file}")

    # 最终汇总
    log("\n=== 合并去重 ===")
    old_urls = _load_previous_urls(output_file)
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


DEFAULT_CONFIG_TEMPLATE = json.dumps({
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
    args = ap.parse_args()

    if not ensure_config(args.config):
        return 1

    config = load_config(args.config)
    try:
        result = run_collect(config, output_file=args.output, log_file=args.logfile)
    except KeyboardInterrupt:
        log("\n[!] 被用户中断")
        return 130
    if not result:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
