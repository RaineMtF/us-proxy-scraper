import asyncio
import builtins
from datetime import datetime, timedelta
import gzip
import json
import os
import queue
import random
import re
import shutil
import sys
import threading
import time
import urllib.parse
import warnings

# ------------------------------
# 忽略第三方库引发的语法/废弃警告 (包括 pyautogui 在 Python 3.12+ 中的 \e 无效转义序列)
# ------------------------------
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)


# ------------------------------
# 全局未捕获底层/析构异常过滤器 (解决 BaseEventLoop.__del__ 与底层 fd: -1 退出警告)
# ------------------------------
def _custom_unraisablehook(unraisable):
    exc_type = unraisable.exc_type
    exc_value = unraisable.exc_value
    err_msg = str(unraisable.err_msg or "")
    val_str = str(exc_value or "")

    # 过滤 asyncio BaseEventLoop 在析构 (__del__) 或进程退出时由于底层 pipe/socket 已提前关闭引发的异常
    if exc_type in (ValueError, RuntimeError, ResourceWarning, OSError):
        if any(
            k in val_str
            for k in (
                "Invalid file descriptor",
                "Event loop is closed",
                "closed pipe",
                "Bad file descriptor",
                "I/O operation on closed pipe",
            )
        ):
            return
        if "BaseEventLoop.__del__" in err_msg:
            return

    if sys.__unraisablehook__:
        try:
            sys.__unraisablehook__(unraisable)
        except Exception:
            pass


sys.unraisablehook = _custom_unraisablehook


def _patch_pyautogui_syntax():
    """检测并就地修正 _pyautogui_x11.py 中 '\\e' 无效转义序列语法警告"""
    try:
        import glob

        for path in sys.path:
            pattern = os.path.join(path, "pyautogui", "_pyautogui_x11.py")
            for f in glob.glob(pattern):
                try:
                    with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                    if content is not None and len(content) < 100:
                        # 若文件被意外清空，通过 pip 强制重装恢复
                        import subprocess

                        subprocess.run(
                            [
                                sys.executable,
                                "-m",
                                "pip",
                                "install",
                                "--force-reinstall",
                                "--no-deps",
                                "pyautogui",
                            ],
                            capture_output=True,
                        )
                        with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()
                    if content and "'\\e':" in content:
                        with open(f, "w", encoding="utf-8") as fp:
                            fp.write(content.replace("'\\e':", "'\\\\e':"))
                except Exception:
                    pass
    except Exception:
        pass


_patch_pyautogui_syntax()

import geoip2.database
import ip2region.searcher as xdb
import ip2region.util as util
import requests
import yaml
from bs4 import BeautifulSoup
from seleniumbase import sb_cdp

# ------------------------------
# 控制台实时刷新配置与线程安全打印锁
# ------------------------------
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True, write_through=True)
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(line_buffering=True, write_through=True)
    except Exception:
        pass

_PRINT_LOCK = threading.Lock()
_original_print = builtins.print


def _thread_safe_print(*args, **kwargs):
    """线程安全、无缓冲立即刷新的 print，确保控制台日志毫秒级实时可见且不交织"""
    if "flush" not in kwargs:
        kwargs["flush"] = True
    with _PRINT_LOCK:
        _original_print(*args, **kwargs)
        try:
            sys.stdout.flush()
        except Exception:
            pass


builtins.print = _thread_safe_print


class ProxyNode:
    """代理节点数据模型，支持基于 (ip, port, type) 的哈希去重、时间戳生命周期追踪与标准 URI 格式化"""

    def __init__(self, data, override_to_https=False):
        data = dict(data) if isinstance(data, dict) else {}
        self.ip = str(data.get("ip", "")).strip()
        self.port = str(data.get("port", "")).strip()
        raw_type = str(data.get("type", "")).strip().lower()
        if override_to_https:
            self.type = "https"
        else:
            self.type = raw_type

        # 规范化 type_list
        raw_types = data.get("type_list")
        if not raw_types or not isinstance(raw_types, list):
            raw_types = [raw_type] if raw_type else []
        norm_types = []
        for t in raw_types:
            t_str = str(t).strip().lower()
            if t_str and t_str not in norm_types:
                norm_types.append(t_str)
        if raw_type and raw_type not in norm_types:
            norm_types.append(raw_type)
        if override_to_https and "https" not in norm_types:
            norm_types.insert(0, "https")

        first_added = str(
            data.get("first_added") or data.get("first_seen") or ""
        ).strip()
        last_added = str(data.get("last_added") or data.get("last_seen") or "").strip()

        self.all = dict(data)
        self.all.update(
            {
                "ip": self.ip,
                "port": self.port,
                "type": self.type,
                "type_list": norm_types,
                "country": str(data.get("country", "")).strip(),
                "country_code": str(data.get("country_code", "")).strip().upper(),
                "city": str(data.get("city", "")).strip(),
                "delay": str(data.get("delay", "")).strip(),
                "anonymity": str(data.get("anonymity", "")).strip(),
            }
        )
        if first_added:
            self.all["first_added"] = first_added
        if last_added:
            self.all["last_added"] = last_added

    @property
    def first_added(self):
        return self.all.get("first_added", "")

    @property
    def last_added(self):
        return self.all.get("last_added", "")

    def __hash__(self):
        return hash((self.ip, self.port, self.type))

    def __eq__(self, other):
        if not isinstance(other, ProxyNode):
            return False
        return (self.ip, self.port, self.type) == (
            other.ip,
            other.port,
            other.type,
        )

    def __repr__(self):
        country_code = str(self.all.get("country_code", "")).strip().upper()
        city = str(self.all.get("city", "")).strip()
        url = f"{self.type}://{self.ip}:{self.port}"
        parts = [
            p for p in [country_code, city, self.type.upper(), self.ip, self.port] if p
        ]
        name = " ".join(parts)
        return f"{url}#{urllib.parse.quote(name)}"


def _parse_time(t_str):
    """解析多种可能的时间格式为 datetime 对象"""
    if not t_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(str(t_str).strip(), fmt)
        except Exception:
            pass
    try:
        return datetime.fromisoformat(str(t_str).strip())
    except Exception:
        return None


def merge_two_nodes(node_a, node_b, is_update_cycle=False, now_str=None):
    """
    深度合并两个相同 (ip, port, type) 的节点数据：
    - 保留最早的 first_added
    - 保留最新的 last_added (若为当前抓取轮次复现则直接更新为 now_str)
    - 协议列表 type_list 合并去重
    - 优先保留更优/非空的 delay (正整数较小者优先)
    - 优先保留非空属性 (anonymity 等)
    - 国家/城市合并：若新节点为 UNK，则遵循不写国家与城市；若非 UNK 则优先保留有效解析城市与国家
    """
    fa_a = str(
        node_a.all.get("first_added") or node_a.all.get("first_seen") or ""
    ).strip()
    fa_b = str(
        node_b.all.get("first_added") or node_b.all.get("first_seen") or ""
    ).strip()
    dt_a = _parse_time(fa_a)
    dt_b = _parse_time(fa_b)
    if dt_a and dt_b:
        first_added = fa_a if dt_a <= dt_b else fa_b
    else:
        first_added = fa_a or fa_b or (now_str or "")

    if is_update_cycle and now_str:
        last_added = now_str
    else:
        la_a = str(
            node_a.all.get("last_added") or node_a.all.get("last_seen") or ""
        ).strip()
        la_b = str(
            node_b.all.get("last_added") or node_b.all.get("last_seen") or ""
        ).strip()
        dt_la_a = _parse_time(la_a)
        dt_la_b = _parse_time(la_b)
        if dt_la_a and dt_la_b:
            last_added = la_a if dt_la_a >= dt_la_b else la_b
        else:
            last_added = la_a or la_b or (now_str or "")

    types_a = (
        node_a.all.get("type_list", [])
        if isinstance(node_a.all.get("type_list"), list)
        else [node_a.type]
    )
    types_b = (
        node_b.all.get("type_list", [])
        if isinstance(node_b.all.get("type_list"), list)
        else [node_b.type]
    )
    combined_types = list(dict.fromkeys(types_a + types_b))

    d_a = str(node_a.all.get("delay", "")).strip()
    d_b = str(node_b.all.get("delay", "")).strip()
    delay = d_a
    if d_a.isdigit() and d_b.isdigit():
        delay = str(min(int(d_a), int(d_b)))
    elif d_b.isdigit():
        delay = d_b
    elif not delay:
        delay = d_b

    anon = (
        str(node_b.all.get("anonymity", "")).strip()
        or str(node_a.all.get("anonymity", "")).strip()
    )

    code_a = str(node_a.all.get("country_code", "")).strip().upper()
    code_b = str(node_b.all.get("country_code", "")).strip().upper()
    country_a = str(node_a.all.get("country", "")).strip()
    country_b = str(node_b.all.get("country", "")).strip()
    city_a = str(node_a.all.get("city", "")).strip()
    city_b = str(node_b.all.get("city", "")).strip()

    if code_b == "UNK":
        country_code = "UNK"
        country = ""
        city = ""
    elif code_a == "UNK" and not code_b:
        country_code = "UNK"
        country = ""
        city = ""
    else:
        country_code = code_b or code_a
        country = country_b or country_a
        city = city_b or city_a

    merged_data = dict(node_a.all)
    merged_data.update(node_b.all)
    merged_data["ip"] = node_a.ip
    merged_data["port"] = node_a.port
    merged_data["type"] = node_b.type or node_a.type
    merged_data["type_list"] = combined_types
    merged_data["first_added"] = first_added
    merged_data["last_added"] = last_added
    merged_data["delay"] = delay
    merged_data["anonymity"] = anon
    merged_data["country_code"] = country_code
    merged_data["country"] = country
    merged_data["city"] = city

    return ProxyNode(merged_data)


def deduplicate_nodes(nodes, override_to_https=False):
    """
    对节点集合进行深度去重合并。
    若开启 override_to_https，所有节点先统一将协议覆写为 https，
    然后根据 (ip, port, 'https') 进行深度属性合并，避免协议覆写导致数据冲突或覆盖丢失。
    """
    dedup_map = {}
    for node in nodes:
        if override_to_https:
            node.type = "https"
            node.all["type"] = "https"
            norm_types = node.all.get("type_list", [])
            if not isinstance(norm_types, list):
                norm_types = [node.type]
            if "https" not in norm_types:
                norm_types.insert(0, "https")
            node.all["type_list"] = norm_types

        key = (node.ip, node.port, node.type)
        if key in dedup_map:
            dedup_map[key] = merge_two_nodes(dedup_map[key], node)
        else:
            dedup_map[key] = node

    return set(dedup_map.values())


# ------------------------------
# 配置解析模块
# ------------------------------
def load_scraper_configs(config_data):
    """
    解析配置数据。
    支持 1: countries 列表 + common_configs 模板自动矩阵组合
    支持 2: configs 额外独立配置列表 (无协议/速度等限制，直接生效)
    支持 3: 历史直接配置的 freeproxy_list 列表
    """

    def _normalize_country(raw_val):
        if raw_val is False:
            return "NO"  # 兼容 YAML 将未加引号的 NO 解析为 False 的情况
        if raw_val is True or raw_val is None:
            return ""
        return str(raw_val).strip().upper()

    configs = []
    countries = config_data.get("countries", [])
    common_configs = config_data.get("common_configs", [])

    # 1. 解析 countries 列表与 common_configs 模板自动矩阵组合
    if countries and common_configs:
        for country in countries:
            c = _normalize_country(country)
            if not c:
                continue
            for item in common_configs:
                if isinstance(item, dict):
                    for proto_name, cfg in item.items():
                        merged_cfg = dict(cfg) if isinstance(cfg, dict) else {}
                        merged_cfg["country"] = c
                        item_name = f"{c}_{proto_name}"
                        configs.append({item_name: merged_cfg})
                elif isinstance(item, str):
                    configs.append(
                        {f"{c}_{item}": {"country": c, "type": item, "speed": 2500}}
                    )

    # 2. 解析额外独立配置列表 configs (例如特定国家单独无限制抓取)
    extra_configs = config_data.get("configs", [])
    if extra_configs:
        for idx, item in enumerate(extra_configs, start=1):
            if isinstance(item, dict):
                # 形式 A: - TW: {country: TW} 或 - TW_all: {country: TW}
                if len(item) == 1 and isinstance(next(iter(item.values())), dict):
                    name, cfg = next(iter(item.items()))
                    cfg_copy = dict(cfg)
                    if "country" in cfg_copy:
                        cfg_copy["country"] = _normalize_country(cfg_copy["country"])
                    configs.append({name: cfg_copy})
                else:
                    # 形式 B: - country: TW (直接键值对)
                    cfg_copy = dict(item)
                    if "country" in cfg_copy:
                        cfg_copy["country"] = _normalize_country(cfg_copy["country"])
                    c = cfg_copy.get("country", "")
                    t = str(cfg_copy.get("type", "")).strip()
                    if c and t:
                        name = f"{c}_{t}"
                    elif c:
                        name = c
                    else:
                        name = f"config_{idx}"
                    configs.append({name: cfg_copy})
            elif isinstance(item, str):
                # 形式 C: - TW (纯字符串形式)
                c = _normalize_country(item)
                if c:
                    configs.append({c: {"country": c}})

    # 3. 兼容直接配置 freeproxy_list 的情况
    if not configs and "freeproxy_list" in config_data:
        configs = config_data["freeproxy_list"]

    # 4. 提取所有允许的目标国家白名单
    allowed_countries = set()
    for item in configs:
        for _, cfg in item.items():
            if isinstance(cfg, dict) and "country" in cfg:
                c = _normalize_country(cfg["country"])
                if c:
                    allowed_countries.add(c)

    for c in countries:
        c_norm = _normalize_country(c)
        if c_norm:
            allowed_countries.add(c_norm)

    return configs, allowed_countries


# ------------------------------
# ProxyScrape 数据抓取模块
# ------------------------------
def fetch_proxyscrape():
    """从 ProxyScrape 抓取预置代理列表"""
    sources = [
        "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/countries/us/socks5/data.json",
        "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/countries/us/socks4/data.json",
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    results = set()
    for url in sources:
        try:
            print(f"[ProxyScrape] 正在请求数据源: {url}")
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code != 200:
                print(f"[ProxyScrape] 请求失败，HTTP 状态码: {response.status_code}")
                continue

            data_items = response.json()
            if not data_items:
                continue

            for item in data_items:
                protocol = item.get("protocol", "socks5").lower()
                proxy_data = {
                    "ip": item.get("ip"),
                    "port": item.get("port"),
                    "type": protocol,
                    "type_list": [protocol],
                    "country": item.get("country", ""),
                    "country_code": item.get("country_code", ""),
                    "city": item.get("city", ""),
                    "delay": item.get("responseTime", ""),
                    "anonymity": item.get("latency_ms", ""),
                }
                results.add(ProxyNode(proxy_data))
        except requests.RequestException as e:
            print(f"[ProxyScrape] 网络请求异常: {e}")
        except Exception as e:
            print(f"[ProxyScrape] 数据解析异常: {e}")

    print(f"[ProxyScrape] 获取完成，提取到 {len(results)} 个节点。\n")
    return results


# ------------------------------
# SeleniumBase CDP 通用并发引擎
# ------------------------------
# CHROMIUM_ARGS = [
#     "--disable-gpu",
#     "--disable-dev-shm-usage",
#     "--no-sandbox",
#     "--disable-extensions",
#     "--disable-setuid-sandbox",
#     "--mute-audio",
#     "--disable-notifications",
#     "--disable-web-security",
#     "--no-first-run",
#     "--no-zygote",
#     # "--headless=new",
#     "--blink-settings=imagesEnabled=false",
# ]

CHROME_ARGS = {
    "uc": True,
    # "headless": False,
    "xvfb": True,
    "xvfb_metrics": "1920,1080",
    "page_load_strategy": "eager",
    "block_images": True,
    "locale": "en",
    "skip_js_waits": True,
    "ad_block_on": True,
    # "chromium_args": ",".join(CHROMIUM_ARGS),
    "use_chromium": False,
    "browser": "chrome",
}

CAPTCHA_LOCK = threading.Lock()


def check_anti_bot_status(soup):
    """检查页面是否被 Cloudflare 盾或验证码拦截"""
    status = {"is_blocked": False, "reason": None, "detail": None}
    if not soup:
        return status

    # 1. 检查 Title
    title_element = soup.title
    title_text = (
        title_element.string.strip() if title_element and title_element.string else ""
    )
    cf_titles = [
        "Just a moment...",
        "Attention Required! | Cloudflare",
        "Please Wait... | Cloudflare",
    ]
    if any(cf_title in title_text for cf_title in cf_titles):
        status["is_blocked"] = True
        status["reason"] = "Cloudflare Challenge Page"
        status["detail"] = f"Matched title: '{title_text}'"
        return status

    # 2. 检查 DOM 元素特征
    if soup.find(id=re.compile(r"^cf-")) or soup.find(class_=re.compile(r"^cf-")):
        status["is_blocked"] = True
        status["reason"] = "Cloudflare Challenge"
        return status

    if (
        soup.find(class_="g-recaptcha")
        or soup.find(id="g-recaptcha")
        or soup.find(class_=re.compile(r"recaptcha", re.I))
    ):
        status["is_blocked"] = True
        status["reason"] = "reCAPTCHA"
        return status

    if soup.find(class_="h-captcha") or soup.find(id="h-captcha"):
        status["is_blocked"] = True
        status["reason"] = "hCaptcha"
        return status

    # 3. 检查脚本
    scripts = soup.find_all("script", src=True)
    for script in scripts:
        src = script["src"].lower()
        if "recaptcha" in src or "turnstile" in src or "hcaptcha" in src:
            status["is_blocked"] = True
            status["reason"] = "Captcha Script Detected"
            return status

    # 4. 检查文本特征
    body_text = soup.get_text().lower()
    if (
        "error code: 1020" in body_text
        or "checking your browser before accessing" in body_text
    ):
        status["is_blocked"] = True
        status["reason"] = "Cloudflare WAF / Verification"
        return status

    return status


def _set_js_disabled(sb, disabled):
    """通过 CDP 命令切换页面 JS 执行开关。"""
    try:
        sb.execute_cdp_cmd("Emulation.setScriptExecutionDisabled", {"value": disabled})
    except Exception:
        pass


def _wait_and_parse(sb):
    """等待页面核心元素加载并返回 BeautifulSoup 对象。"""
    try:
        sb.assert_element("table tr, div.pagination", timeout=5)
    except Exception:
        pass
    return sb.get_beautiful_soup()


def _safe_close_sb(sb):
    """安全关闭 SeleniumBase CDP 实例并清理关联的 asyncio 事件循环"""
    if not sb:
        return
    try:
        if hasattr(sb, "driver") and sb.driver:
            sb.driver.stop()
        elif hasattr(sb, "quit"):
            sb.quit()
    except Exception:
        pass

    try:
        loop = getattr(sb, "loop", None)
        if loop and not loop.is_closed():
            loop.close()
    except Exception:
        pass


def fetch_page_with_cdp(sb, url, parser_fn, thread_id=""):
    """
    使用现有的 sb 实例打开 url，分级反爬策略：
      Phase 1: 禁用 JS（最快） → 检查是否被拦截
      Phase 2: 启用 JS 并重新加载 → 检查是否被拦截
      Phase 3: 自动点击验证码 → 检查是否被拦截
      Phase 4: 跳过该页面
    """
    # ── Phase 1: 禁用 JS，以最快速度加载页面 ──
    _set_js_disabled(sb, True)
    sb.activate_cdp_mode(url)
    bs4_data = _wait_and_parse(sb)
    anti_bot = check_anti_bot_status(bs4_data)

    if not anti_bot["is_blocked"]:
        _set_js_disabled(sb, False)  # 恢复默认，避免影响后续请求
        return parser_fn(bs4_data)

    # ── Phase 2: 启用 JS 后重新加载 ──
    print(
        f"[Worker {thread_id}] 无 JS 被拦截 ({anti_bot['reason']})，启用 JS 重试: {url}"
    )
    _set_js_disabled(sb, False)
    sb.activate_cdp_mode(url)
    bs4_data = _wait_and_parse(sb)
    anti_bot = check_anti_bot_status(bs4_data)

    if not anti_bot["is_blocked"]:
        return parser_fn(bs4_data)

    # ── Phase 3: 自动点击验证码 ──
    with CAPTCHA_LOCK:
        print(
            f"[Worker {thread_id}] 仍被拦截 ({anti_bot['reason']})，尝试自动点击验证码: {url}"
        )
        _patch_pyautogui_syntax()
        sb.gui_click_captcha()
    bs4_data = _wait_and_parse(sb)
    anti_bot = check_anti_bot_status(bs4_data)

    if not anti_bot["is_blocked"]:
        return parser_fn(bs4_data)

    # ── Phase 4: 所有手段均失败，抛出异常触发上层重试 ──
    print(
        f"[Worker {thread_id}] 所有反爬手段均失败被拦截 ({anti_bot['reason']}): {url}"
    )
    raise RuntimeError(f"反爬拦截未通过: {anti_bot['reason']}")


_BROWSER_INIT_LOCK = threading.Lock()


def run_cdp_task_queue(tasks, process_task_fn, max_workers=16):
    """
    通用 CDP 线程池任务调度器。
    """
    if not tasks:
        return []

    task_queue = queue.Queue()
    for task in tasks:
        task_queue.put(task)

    results = []
    results_lock = threading.Lock()
    total_tasks = len(tasks)
    completed_counter = [0]
    counter_lock = threading.Lock()
    actual_workers = min(max_workers, total_tasks)

    def worker():
        sb = None
        thread_id = str(threading.get_ident())[-4:]

        try:
            while True:
                try:
                    task_item = task_queue.get_nowait()
                except queue.Empty:
                    break

                # 浏览器启动失败自动重试机制 (加锁串行化初始化，彻底杜绝并发抢占 X11/Xvfb 显示服务和端口引发的 Errno 111)
                if sb is None:
                    max_init_retries = 3
                    for attempt in range(1, max_init_retries + 1):
                        try:
                            print(
                                f"[Worker {thread_id}] 正在初始化 Chrome 浏览器内核 (尝试 {attempt}/{max_init_retries})..."
                            )
                            with _BROWSER_INIT_LOCK:
                                sb = sb_cdp.Chrome(**CHROME_ARGS)
                                time.sleep(0.1)
                            break
                        except Exception as e:
                            print(
                                f"[Worker {thread_id}] Chrome 启动失败 (尝试 {attempt}/{max_init_retries}): {e}"
                            )
                            _safe_close_sb(sb)
                            sb = None
                            if attempt < max_init_retries:
                                time.sleep(1.5 * attempt)

                    if sb is None:
                        print(
                            f"[Worker {thread_id}] Chrome 连续 {max_init_retries} 次启动均失败，Worker 退出并将任务放回队列"
                        )
                        task_queue.put(task_item)
                        task_queue.task_done()
                        break

                start_t = time.time()

                try:
                    res = process_task_fn(sb, task_item, thread_id)
                    if res is not None:
                        with results_lock:
                            results.append(res)
                except Exception as e:
                    duration = time.time() - start_t
                    if duration >= 9.9:
                        print(
                            f"[Worker {thread_id}] !! 任务强制超时 (10s) 自动终止: {task_item}"
                        )
                    else:
                        print(f"[Worker {thread_id}] 任务执行失败: {e}")
                    _safe_close_sb(sb)
                    sb = None
                finally:
                    with counter_lock:
                        completed_counter[0] += 1
                    task_queue.task_done()
        finally:
            _safe_close_sb(sb)
            sb = None
            try:
                loop = asyncio.get_event_loop_policy().get_event_loop()
                if loop and not loop.is_closed():
                    loop.close()
            except Exception:
                pass

    threads = []
    for _ in range(actual_workers):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        time.sleep(0.05)
        threads.append(t)

    task_queue.join()
    for t in threads:
        t.join(timeout=5)
    return results


# ------------------------------
# FreeProxy World 数据解析与批量任务
# ------------------------------
def extract_proxies(soup):
    """从页面表格中提取代理节点"""
    results = []
    trs = soup.find_all("tr")
    for tr in trs:
        tds = tr.find_all("td")
        if len(tds) < 7:
            continue
        try:
            proxy_type_list = tds[5].get_text(separator=" ", strip=True).split(" ")
            best_type = proxy_type_list[-1].lower()

            ip = tds[0].get_text(strip=True)
            port = tds[1].get_text(strip=True)

            delay_text = tds[4].get_text(strip=True)
            delay_match = re.search(r"\d+", delay_text)
            delay = delay_match.group(0) if delay_match else ""

            country = tds[2].get_text(strip=True)
            city = tds[3].get_text(strip=True)

            country_code = ""
            country_a = tds[2].find("a")
            if country_a and "href" in country_a.attrs:
                code_match = re.search(r"country=([A-Za-z]+)", country_a["href"])
                if code_match:
                    country_code = code_match.group(1).upper()

            anonymity = ""
            anon_a = tds[6].find("a")
            if anon_a and "href" in anon_a.attrs:
                anon_match = re.search(r"anonymity=(\d+)", anon_a["href"])
                if anon_match:
                    anonymity = anon_match.group(1)

            proxy_data = {
                "ip": ip,
                "port": port,
                "type": best_type,
                "type_list": proxy_type_list,
                "country": country,
                "country_code": country_code,
                "city": city,
                "delay": delay,
                "anonymity": anonymity,
            }
            results.append(proxy_data)
        except Exception as e:
            print(f"解析代理数据行出错: {e}")
            continue

    return results


def get_total_pages(soup):
    """从分页栏获取最大页码；若页面提示 Found 0 proxies 则返回 0"""
    if soup:
        body_text = soup.get_text()
        if re.search(r"Found\s+0\s+proxies?", body_text, re.I):
            return 0

    pagination_div = soup.find("div", class_="pagination")
    if not pagination_div:
        return 1

    page_numbers = []
    for a_tag in pagination_div.find_all("a"):
        text = a_tag.get_text(strip=True)
        if text.isdigit():
            page_numbers.append(int(text))

    return max(page_numbers) if page_numbers else 1


def _fetch_pagemax_task(sb, task, thread_id):
    """Worker 探测单配置最大页码"""
    name = task["name"]
    url = task["url"]
    config = task["config"]
    start_t = time.time()
    try:
        print(f"[Worker {thread_id}] 正在探测页码: [{name}] {url}")
        total_pages = fetch_page_with_cdp(sb, url, get_total_pages, thread_id)
        elapsed = time.time() - start_t
        print(
            f"[Worker {thread_id}] [{name}] 页码探测成功: 共 {total_pages} 页 (耗时: {elapsed:.1f}s)"
        )
        return {
            "name": name,
            "config": config,
            "total_pages": total_pages,
            "success": True,
        }
    except Exception as e:
        print(f"[Worker {thread_id}] [{name}] 获取最大页码失败: {e}")
        return {"name": name, "config": config, "url": url, "success": False}


def _fetch_proxies_task(sb, url, thread_id):
    """Worker 抓取单个页面的代理节点"""
    start_t = time.time()
    try:
        print(f"[Worker {thread_id}] 开始处理页面: {url}")
        proxies = fetch_page_with_cdp(sb, url, extract_proxies, thread_id)
        elapsed = time.time() - start_t
        if not proxies:
            print(
                f"[Worker {thread_id}] 页面未提取到有效代理 (可能加载不全或反爬拦截): {url}"
            )
            return {"url": url, "nodes": [], "success": False}
        print(
            f"[Worker {thread_id}] 页面抓取成功: {url} (提取 {len(proxies)} 个节点, 耗时 {elapsed:.1f}s)"
        )
        return {"url": url, "nodes": [ProxyNode(p) for p in proxies], "success": True}
    except Exception as e:
        print(f"[Worker {thread_id}] 抓取页面异常: {url} -> {e}")
        return {"url": url, "nodes": [], "success": False}


def batch_fetch_pagemax(configs, max_workers=16):
    """多线程并发探测所有配置的最大页码数，支持重试 1 次"""
    tasks = []
    for item in configs:
        name, config = next(iter(item.items()))
        base_url = f"https://www.freeproxy.world/?{urllib.parse.urlencode(config)}"
        tasks.append({"name": name, "config": config, "url": base_url})

    worker_count = min(max_workers, len(tasks))
    print(
        f"\n[阶段 1/2] 启动 {worker_count} 个并发 Worker 探测 {len(tasks)} 个配置的最大页码..."
    )
    round1_results = run_cdp_task_queue(
        tasks, _fetch_pagemax_task, max_workers=max_workers
    )

    successful = {r["name"]: r for r in round1_results if r.get("success")}
    failed_tasks = [t for t in tasks if t["name"] not in successful]

    if failed_tasks:
        print(
            f"\n[阶段 1/2] 检测到 {len(failed_tasks)} 个配置探测失败，等待 2 秒后进行重试..."
        )
        time.sleep(2)
        round2_results = run_cdp_task_queue(
            failed_tasks, _fetch_pagemax_task, max_workers=max_workers
        )
        for r in round2_results:
            if r.get("success"):
                successful[r["name"]] = r

    print(
        f"[阶段 1/2 完成] 最大页码探测完毕，有效配置: {len(successful)}/{len(tasks)} 个。\n"
    )
    return list(successful.values())


def batch_fetch_proxies(urls, max_workers=16):
    """多线程并发抓取所有目标页面，支持失败重试 1 次"""
    worker_count = min(max_workers, len(urls))
    print(
        f"\n[阶段 2/2] 启动 {worker_count} 个并发 Worker 抓取全部 {len(urls)} 个目标页面..."
    )
    round1_results = run_cdp_task_queue(
        urls, _fetch_proxies_task, max_workers=max_workers
    )

    successful_urls = {r["url"] for r in round1_results if r.get("success")}
    all_nodes = set()
    for r in round1_results:
        if r.get("success"):
            all_nodes.update(r.get("nodes", []))

    failed_urls = [u for u in urls if u not in successful_urls]
    if failed_urls:
        print(
            f"\n[阶段 2/2] 检测到 {len(failed_urls)} 个页面抓取失败，等待 2 秒后进行重试 1 次..."
        )
        time.sleep(2)
        round2_results = run_cdp_task_queue(
            failed_urls, _fetch_proxies_task, max_workers=max_workers
        )
        for r in round2_results:
            if r.get("success"):
                all_nodes.update(r.get("nodes", []))
                successful_urls.add(r["url"])

        still_failed = [u for u in failed_urls if u not in successful_urls]
        if still_failed:
            print(
                f"[阶段 2/2] 重试后仍有 {len(still_failed)} 个页面抓取失败，已跳过。\n"
            )
        else:
            print(f"[阶段 2/2] 重试完成，所有失败页面均成功抓取！\n")

    print(f"[阶段 2/2 完成] 目标页面抓取完毕，共提取到 {len(all_nodes)} 个代理节点。\n")
    return all_nodes


# ------------------------------
# 多源 IP 归属地四源交叉复核与审阅模块
# (上游抓取源 + DbIP-City-lite + GeoLite2-City + ip2region)
# ------------------------------
def review_and_filter_proxies(
    proxy_nodes,
    allowed_countries,
    blacklist=None,
    geolite_path="GeoLite2-City.mmdb",
    dbip_path="dbip-city-lite.mmdb",
    ip2region_path="ip2region_v4.xdb",
):
    """
    使用四源进行多重交叉审阅与验证：
    1. 上游直接抓取的国家代码 (node.country_code)
    2. DbIP-City-lite（本地主库：决定最终写入的 country, country_code, city）
    3. GeoLite2-City（本地交叉库 1：取 country_code）
    4. ip2region_v4.xdb（本地交叉库 2：取 country_code）

    规则：
    - 优先检查 IP 黑名单；
    - 如果识别到了非所需国家还是删除：只要有任何一个来源识别出非白名单国家，直接剔除；
    - 所有来源均未识别出有效国家代码的，直接剔除；
    - 必须四个来源库全都一致认为是这个国家才标注，城市按照原有 DbIP 逻辑选择；
    - 如果识别到的都在可行国家中，但并非全部一致认为是某一个国家，一律设为 UNK，不写国家和地区/城市（保留节点不删除）。
    """
    blacklist_set = {str(ip).strip() for ip in (blacklist or []) if str(ip).strip()}
    allowed_set = {c.strip().upper() for c in allowed_countries if c and c.strip()}
    if "US" in allowed_set:
        allowed_set.add("USA")
    filtered_nodes = set()
    dropped_country_codes = set()
    total_count = len(proxy_nodes)
    dropped_count = 0
    blacklisted_count = 0
    unanimous_count = 0
    unk_count = 0

    # 初始化 Readers
    geo_reader = None
    if os.path.exists(geolite_path):
        try:
            geo_reader = geoip2.database.Reader(geolite_path)
        except Exception as e:
            print(f"[GeoLite2] 初始化失败: {e}")
    else:
        print(f"[GeoLite2] 警告: 未找到 {geolite_path}")

    dbip_reader = None
    if os.path.exists(dbip_path):
        try:
            dbip_reader = geoip2.database.Reader(dbip_path)
        except Exception as e:
            print(f"[DbIP] 初始化失败: {e}")
    else:
        print(f"[DbIP] 警告: 未找到 {dbip_path}")

    ip2reg_searcher = None
    if os.path.exists(ip2region_path):
        try:
            c_buffer = util.load_content_from_file(ip2region_path)
            ip2reg_searcher = xdb.new_with_buffer(util.IPv4, c_buffer)
        except Exception as e:
            print(f"[ip2region] 初始化失败: {e}")
    else:
        print(f"[ip2region] 警告: 未找到 {ip2region_path}")

    if not dbip_reader:
        print(
            "[DbIP] 警告: 未找到主库 DbIP-City-lite，执行备用白名单与黑名单基础核验。"
        )
        for node in proxy_nodes:
            ip = node.ip
            if blacklist_set and ip in blacklist_set:
                blacklisted_count += 1
                continue
            raw_upstream = str(node.all.get("country_code", "")).strip().upper()
            upstream_code = "US" if raw_upstream in ("US", "USA") else raw_upstream
            if allowed_set and upstream_code and upstream_code not in allowed_set:
                dropped_count += 1
                dropped_country_codes.add(upstream_code)
                continue
            # 缺失本地主库时无法完成四源一致验证，标记为 UNK，不写国家和城市
            node.all["country_code"] = "UNK"
            node.all["country"] = ""
            node.all["city"] = ""
            filtered_nodes.add(node)
        print(f"[阶段 3/3 完成] 备用核验完毕：共保留 {len(filtered_nodes)} 个节点。")
        if geo_reader:
            try:
                geo_reader.close()
            except Exception:
                pass
        return filtered_nodes

    print(
        f"[阶段 3/3] 开始对 {total_count} 个节点执行四源交叉归属地审阅 (白名单国家: {len(allowed_set)} 个, 黑名单 IP: {len(blacklist_set)} 个)..."
    )

    for node in proxy_nodes:
        ip = node.ip

        # 1. 优先黑名单拦截
        if blacklist_set and ip in blacklist_set:
            blacklisted_count += 1
            continue

        # 来源 1：上游直接抓取的国家代码
        raw_upstream = str(node.all.get("country_code", "")).strip().upper()
        upstream_code = "US" if raw_upstream in ("US", "USA") else raw_upstream

        # 来源 2：DbIP-City-lite（本地主库：取 country_code / country / city）
        dbip_code = ""
        dbip_country = ""
        dbip_city = ""
        try:
            d_res = dbip_reader.city(ip)
            raw_d = str(d_res.country.iso_code or "").strip().upper()
            dbip_code = "US" if raw_d in ("US", "USA") else raw_d
            dbip_country = str(d_res.country.name or "").strip()
            _city_name = str(d_res.city.name or "").strip()
            _sub_name = ""
            try:
                _sub_name = str(d_res.subdivisions.most_specific.name or "").strip()
            except Exception:
                _sub_name = ""
            # city 优先取省份/州 (subdivisions)，为空时回退到 city.name
            if _sub_name and _sub_name not in ("", "0"):
                dbip_city = _sub_name
            elif _city_name and _city_name not in ("", "0"):
                dbip_city = _city_name
            else:
                dbip_city = ""
        except Exception:
            pass

        # 来源 3：GeoLite2-City（本地交叉库 1：仅取 country_code）
        geo_code = ""
        if geo_reader:
            try:
                g_res = geo_reader.city(ip)
                raw_g = str(g_res.country.iso_code or "").strip().upper()
                geo_code = "US" if raw_g in ("US", "USA") else raw_g
            except Exception:
                pass

        # 来源 4：ip2region_v4.xdb（本地交叉库 2：仅取 country_code）
        ip2reg_code = ""
        if ip2reg_searcher:
            try:
                reg_str = ip2reg_searcher.search(ip)
                parts = reg_str.split("|")
                # 格式: 国家|省份|城市|ISP|国家代码
                if len(parts) >= 5 and parts[4] not in ("", "0"):
                    raw_i = str(parts[4]).strip().upper()
                    ip2reg_code = "US" if raw_i in ("US", "USA") else raw_i
                elif len(parts) >= 1 and parts[0].strip().upper() in ("US", "USA"):
                    ip2reg_code = "US"
            except Exception:
                pass

        # 四源审阅逻辑：
        # 1. 提取所有来源已解析出的非空国家代码
        sources = [upstream_code, dbip_code, geo_code, ip2reg_code]
        detected_codes = [c for c in sources if c]

        # 若没有任何一个来源解析出有效国家代码，无法核验，剔除
        if not detected_codes:
            dropped_count += 1
            continue

        # 2. 如果识别到了非所需国家还是删除：只要有任何一个非空来源的代码不在白名单中，立即剔除
        disallowed_found = False
        for c in detected_codes:
            if c not in allowed_set:
                disallowed_found = True
                dropped_country_codes.add(c)
        if disallowed_found:
            dropped_count += 1
            continue

        # 3. 此时所有已识别的国家代码均在白名单中
        # 必须四个来源库全都一致认为是这个国家才标注
        is_four_unanimous = (
            bool(upstream_code)
            and bool(dbip_code)
            and bool(geo_code)
            and bool(ip2reg_code)
            and (upstream_code == dbip_code == geo_code == ip2reg_code)
        )

        if is_four_unanimous:
            # 四个来源完全一致认定：标注该国家，城市按 DbIP 原逻辑写入
            target_country = dbip_code
            if dbip_country:
                node.all["country"] = dbip_country
            node.all["country_code"] = target_country
            if dbip_city or dbip_country:
                node.all["city"] = dbip_city
            unanimous_count += 1
        else:
            # 识别到的都在可行国家中，但并非四个全部一致认定为某一个国家，标记为 UNK，不写国家和地区
            node.all["country_code"] = "UNK"
            node.all["country"] = ""
            node.all["city"] = ""
            unk_count += 1

        filtered_nodes.add(node)

    # 关闭 readers
    if geo_reader:
        try:
            geo_reader.close()
        except Exception:
            pass
    if dbip_reader:
        try:
            dbip_reader.close()
        except Exception:
            pass

    print(
        f"[阶段 3/3 完成] 四源交叉复核完毕：共检验 {total_count} 个节点，黑名单拦截 {blacklisted_count} 个，剔除 {dropped_count} 个不合格节点，最终保留 {len(filtered_nodes)} 个节点 (其中四个完全一致标注: {unanimous_count} 个, 未知标记 UNK: {unk_count} 个)。"
    )
    if dropped_country_codes:
        print(
            f"[GeoDB] 剔除节点的国家代码汇总 (共 {len(dropped_country_codes)} 个): {sorted(dropped_country_codes)}\n"
        )
    else:
        print(f"[GeoDB] 未剔除任何国家节点。\n")

    return filtered_nodes


# ------------------------------
# 历史数据加载、去重合并与过期清理模块
# ------------------------------
def is_older_than_days(date_str, now_dt, max_days=30):
    """判断日期字符串距今是否超过 max_days 天"""
    if not date_str:
        return False
    try:
        dt = datetime.fromisoformat(str(date_str).strip())
        return (now_dt - dt) > timedelta(days=max_days)
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.strptime(str(date_str).strip(), fmt)
                return (now_dt - dt) > timedelta(days=max_days)
            except Exception:
                pass
    return False


def load_raw_proxies(
    filepath="data/raw.json", default_time_str=None, override_to_https=False
):
    """
    启动时读取历史 raw.json 数据。
    若存在缺失首次或最后添加时间戳的旧节点，自动为其补充默认时间戳。
    若开启 override_to_https，所有历史节点统一覆写为 https 并通过 merge_two_nodes 深度合并去重。
    返回字典: { (ip, port, type): ProxyNode }
    """
    if not os.path.exists(filepath):
        print(f"[历史数据] 未检测到历史文件 {filepath}，本次启动将作为首次抓取运行。")
        return {}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[历史数据] 读取 {filepath} 失败: {e}，将作为首次抓取运行。")
        return {}

    if not isinstance(data, list):
        print(f"[历史数据] 文件 {filepath} 格式非 JSON 列表，忽略。")
        return {}

    historical_map = {}
    missing_time_count = 0
    now_str = default_time_str or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for item in data:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip", "")).strip()
        port = str(item.get("port", "")).strip()
        p_type = str(item.get("type", "")).strip().lower()
        if not ip or not port:
            continue
        if not p_type and not override_to_https:
            continue

        first_added = str(
            item.get("first_added") or item.get("first_seen") or ""
        ).strip()
        last_added = str(item.get("last_added") or item.get("last_seen") or "").strip()

        if not first_added or not last_added:
            missing_time_count += 1
            if not first_added:
                first_added = now_str
            if not last_added:
                last_added = now_str
            item["first_added"] = first_added
            item["last_added"] = last_added

        node = ProxyNode(item, override_to_https=override_to_https)
        key = (node.ip, node.port, node.type)
        if key in historical_map:
            # 协议覆写后发生 (ip, port, https) 碰撞时深度合并去重
            historical_map[key] = merge_two_nodes(historical_map[key], node)
        else:
            historical_map[key] = node

    print(
        f"[历史数据] 成功从 {filepath} 载入 {len(historical_map)} 个历史节点"
        + (
            f" (已为 {missing_time_count} 个旧格式节点补齐初次与最后时间戳)"
            if missing_time_count
            else ""
        )
        + "。"
    )
    return historical_map


def merge_and_prune_proxies(
    historical_map,
    new_nodes,
    allowed_countries,
    blacklist=None,
    now_dt=None,
    max_age_days=30,
    override_to_https=False,
):
    """
    合并历史节点与本轮新核验节点，并执行完善去重与超期删除：
    1. 节点去重与时间戳更新：
       - 若节点已在历史库中且本轮再次抓取到：保留原 first_added，更新 last_added 为当前时间，更新最新 delay/city/type_list 等属性；
       - 若节点为全新节点：first_added 与 last_added 均记为当前时间；
       - 若节点仅在历史库但本轮未抓取到：保留原 first_added 与 last_added。
    2. 黑名单过滤：剔除所有 IP 在 blacklist 中的节点。
    3. 国家白名单过滤：剔除 country_code 不在 allowed_countries 中的节点 (UNK 节点保留)。
    4. 30天（1个月）过期清理：若节点的 last_added 距今远于 30 天，则彻底清理删除。
    """
    if now_dt is None:
        now_dt = datetime.now()
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    blacklist_set = {str(ip).strip() for ip in (blacklist or []) if str(ip).strip()}
    allowed_set = {
        c.strip().upper() for c in (allowed_countries or []) if c and c.strip()
    }
    if "US" in allowed_set:
        allowed_set.add("USA")

    merged_map = dict(historical_map)
    new_added_count = 0
    updated_count = 0

    for node in new_nodes:
        if override_to_https:
            node.type = "https"
            node.all["type"] = "https"
            norm_types = node.all.get("type_list", [])
            if not isinstance(norm_types, list):
                norm_types = [node.type]
            if "https" not in norm_types:
                norm_types.insert(0, "https")
            node.all["type_list"] = norm_types

        key = (node.ip, node.port, node.type)
        if key in merged_map:
            # 历史已有：通过 merge_two_nodes 深度合并更新，保留最早 first_added，更新 last_added
            old_node = merged_map[key]
            merged_map[key] = merge_two_nodes(
                old_node, node, is_update_cycle=True, now_str=now_str
            )
            updated_count += 1
        else:
            # 全新添加的节点
            node.all["first_added"] = now_str
            node.all["last_added"] = now_str
            merged_map[key] = node
            new_added_count += 1

    # 执行过滤与过期清理
    final_nodes = []
    expired_count = 0
    blacklisted_count = 0
    country_dropped_count = 0

    for key, node in merged_map.items():
        ip = node.ip
        # 1. 黑名单过滤
        if blacklist_set and ip in blacklist_set:
            blacklisted_count += 1
            continue

        # 2. 国家白名单过滤 (UNK 节点为多源审阅不完全一致但均在白名单内的保留节点，不予过滤)
        code = str(node.all.get("country_code", "")).strip().upper()
        if code != "UNK" and allowed_set and (not code or code not in allowed_set):
            country_dropped_count += 1
            continue

        # 3. 30天（1个月）过期清理
        last_added_str = str(
            node.all.get("last_added") or node.all.get("last_seen") or ""
        ).strip()
        if is_older_than_days(last_added_str, now_dt, max_days=max_age_days):
            expired_count += 1
            continue

        final_nodes.append(node)

    print(f"\n[节点合并与去重总结]")
    print(f" - 历史基线节点数: {len(historical_map)} 个")
    print(f" - 本轮新增节点数: {new_added_count} 个")
    print(f" - 本轮更新/复现节点数: {updated_count} 个")
    print(f" - 黑名单拦截剔除: {blacklisted_count} 个")
    print(f" - 国家白名单拦截剔除: {country_dropped_count} 个")
    print(f" - 超过 {max_age_days} 天未遇到/过期清理: {expired_count} 个")
    print(f" - 最终合并保留有效节点数: {len(final_nodes)} 个\n")

    return final_nodes


# ------------------------------
# 主执行流程
# ------------------------------
def main():
    start_all_time = time.time()
    now_dt = datetime.now()
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    config_path = "config.yml"
    with open(config_path, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f)

    override_to_https = bool(
        config_data.get("override_to_https") or config_data.get("force_https")
    )
    freeproxy_only = config_data.get("freeproxy_only", False)
    maxpages = config_data.get("maxpages", 150)
    blacklist = config_data.get("blacklist", [])

    # 解析配置矩阵
    configs, allowed_countries = load_scraper_configs(config_data)

    print(f"==================================================")
    print(f" US-Proxy-Scraper 自动化抓取任务启动")
    print(f" - 执行时间: {now_str}")
    print(f" - override_to_https: {override_to_https}")
    print(f" - freeproxy_only: {freeproxy_only}")
    print(f" - maxpages: {maxpages}")
    print(f" - 黑名单 IP 数量: {len(blacklist)} 个")
    print(f" - 目标国家数: {len(allowed_countries)} 个 ({sorted(allowed_countries)})")
    print(f" - 生成抓取配置数: {len(configs)} 个")
    print(f"==================================================\n")

    # 阶段 0：启动时首先从 data 读取上一次的 raw.json 历史数据
    historical_proxies = load_raw_proxies(
        "data/raw.json", default_time_str=now_str, override_to_https=override_to_https
    )

    scraped_results = set()

    if freeproxy_only:
        print("[配置] 已开启 freeproxy_only，仅抓取 FreeProxy World 数据源。")
    else:
        print("[配置] 正在加载 ProxyScrape 初始数据源...")
        scraped_results.update(fetch_proxyscrape())

    # 阶段 1：并发探测最大页码
    pagemax_results = batch_fetch_pagemax(configs, max_workers=16)

    # 聚合生成待抓取 URL
    collected_urls = []
    for item in pagemax_results:
        name = item["name"]
        config = item["config"]
        valid_pagemax = item["total_pages"]
        base_url = f"https://www.freeproxy.world/?{urllib.parse.urlencode(config)}"

        pages_to_fetch = min(valid_pagemax, maxpages)
        pagelist = random.sample(range(1, valid_pagemax + 1), pages_to_fetch)

        for page in pagelist:
            collected_urls.append(f"{base_url}&page={page}")

    # URL 全局去重（保留顺序）
    all_target_urls = list(dict.fromkeys(collected_urls))
    print(
        f"\n[URL 汇总] 共生成 {len(collected_urls)} 个页面请求，去重后为 {len(all_target_urls)} 个独立待抓取 URL。"
    )

    # 阶段 2：多线程全局并发抓取
    if all_target_urls:
        freeproxy_results = batch_fetch_proxies(all_target_urls, max_workers=16)
        scraped_results.update(freeproxy_results)

    # 对新抓取的节点执行基于 (ip, port, type) 的深度去重合并
    if scraped_results:
        scraped_results = deduplicate_nodes(
            scraped_results, override_to_https=override_to_https
        )

    # 阶段 3：多源 IP 归属地四源交叉审阅 (核验本轮新抓取节点)
    verified_new_nodes = review_and_filter_proxies(
        scraped_results, allowed_countries, blacklist=blacklist
    )

    # 阶段 4：合并历史节点与新抓取节点，完善去重，清理超过1个月未遇到的过期节点
    all_results = merge_and_prune_proxies(
        historical_proxies,
        verified_new_nodes,
        allowed_countries,
        blacklist=blacklist,
        now_dt=now_dt,
        max_age_days=30,
        override_to_https=override_to_https,
    )

    # 导出保存 (输出前按 IP 的 a.b.c.d 升序、端口升序排序)
    def ip_sort_key(node):
        try:
            ip_parts = tuple(int(x) for x in str(node.ip).split("."))
        except Exception:
            ip_parts = (9999, 9999, 9999, 9999)
        port_num = int(node.port) if str(node.port).isdigit() else 99999
        return (ip_parts, port_num, str(node.type))

    all_results = sorted(all_results, key=ip_sort_key)

    os.makedirs("data", exist_ok=True)

    output = [result.all for result in all_results]
    with open("data/raw.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    with open("data/raw.txt", "w", encoding="utf-8") as f:
        for result in all_results:
            f.write(repr(result) + "\n")

    total_duration = time.time() - start_all_time
    print(f"==================================================")
    print(f" 全部任务执行完毕！(总耗时: {total_duration:.1f}s)")
    print(f" 最终导出有效代理节点: {len(output)} 个")
    print(f" 保存路径: data/raw.json, data/raw.txt")
    print(f"==================================================")


if __name__ == "__main__":
    main()
