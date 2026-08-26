import builtins
import json
import os
import queue
import random
import re
import threading
import time
import urllib.parse

import ip2region.searcher as xdb
import ip2region.util as util
import requests
import yaml
from bs4 import BeautifulSoup
from seleniumbase import sb_cdp

# ------------------------------
# 全局线程安全打印锁
# ------------------------------
_PRINT_LOCK = threading.Lock()
_original_print = builtins.print


def _thread_safe_print(*args, **kwargs):
    """线程安全且自动 flush 的 print，避免多线程并发输出交织"""
    if "flush" not in kwargs:
        kwargs["flush"] = True
    with _PRINT_LOCK:
        _original_print(*args, **kwargs)


builtins.print = _thread_safe_print


class ProxyNode:
    """代理节点数据模型，支持去重和标准 URI 格式化"""

    def __init__(self, data):
        self.ip = data.get("ip", "")
        self.port = data.get("port", "")
        self.type = data.get("type", "").lower()
        self.all = data

    def __hash__(self):
        return hash((self.ip, str(self.port), self.type))

    def __eq__(self, other):
        if not isinstance(other, ProxyNode):
            return False
        return (self.ip, str(self.port), self.type) == (
            other.ip,
            str(other.port),
            other.type,
        )

    def __repr__(self):
        country_code = self.all.get("country_code", "")
        country = self.all.get("country", "")
        city = self.all.get("city", "")
        name = urllib.parse.quote(
            f"{country_code} {self.type.upper()} ({city}, {country}) {self.ip}:{self.port}"
        )
        return f"{self.type}://{self.ip}:{self.port}#{name}"


# ------------------------------
# ProxyScrape 数据抓取模块
# ------------------------------
def fetch_proxyscrape():
    """从 ProxyScrape 抓取代理列表"""
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
                print(f"[ProxyScrape] 请求失败，状态码: {response.status_code}")
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
            print(f"[ProxyScrape] 请求网络异常: {e}")
        except Exception as e:
            print(f"[ProxyScrape] 解析异常: {e}")

    print(f"[ProxyScrape] 共获取 {len(results)} 个节点")
    return results


# ------------------------------
# SeleniumBase CDP 通用并发引擎
# ------------------------------
CHROMIUM_ARGS = [
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--no-sandbox",
    "--disable-extensions",
    "--disable-setuid-sandbox",
    "--mute-audio",
    "--disable-notifications",
    "--disable-web-security",
    "--no-first-run",
    "--no-zygote",
    "--headless=new",
    "--blink-settings=imagesEnabled=false",
]

CHROME_ARGS = {
    "uc": True,
    "headless": False,
    "xvfb": True,
    "pls": "eager",
    "block_images": True,
    "locale": "en",
    "skip_js_waits": True,
    "ad_block_on": True,
    "chromium_args": ",".join(CHROMIUM_ARGS),
}

CAPTCHA_LOCK = threading.Lock()


def check_anti_bot_status(soup):
    """检查页面是否被 Cloudflare 盾或验证码拦截"""
    status = {"is_blocked": False, "reason": None, "detail": None}
    if not soup:
        return status

    # 1. 检查页面 Title
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
    if "error code: 1020" in body_text or "checking your browser before accessing" in body_text:
        status["is_blocked"] = True
        status["reason"] = "Cloudflare WAF / Verification"
        return status

    return status


def fetch_page_with_cdp(sb, url, parser_fn):
    """
    使用现有的 sb 实例打开 url，自动处理反爬与验证码，并调用 parser_fn 解析 soup。
    """
    sb.open(url)
    try:
        sb.assert_element("table tr, div.pagination", timeout=5)
    except Exception:
        pass

    bs4_data = sb.get_beautiful_soup()
    if check_anti_bot_status(bs4_data)["is_blocked"]:
        with CAPTCHA_LOCK:
            print(f"[Anti-Bot] 检测到验证码，点击验证码: {url}")
            sb.gui_click_captcha()
        try:
            sb.assert_element("table tr, div.pagination", timeout=5)
        except Exception:
            pass
        bs4_data = sb.get_beautiful_soup()

    return parser_fn(bs4_data)


def run_cdp_task_queue(tasks, process_task_fn, max_workers=8):
    """
    通用 CDP 线程池任务调度器。
    :param tasks: 待处理的任务列表
    :param process_task_fn: 具体的任务处理函数 (sb, task_item) -> result
    :param max_workers: 最大并发数
    :return: 结果列表
    """
    if not tasks:
        return []

    task_queue = queue.Queue()
    for task in tasks:
        task_queue.put(task)

    results = []
    results_lock = threading.Lock()
    actual_workers = min(max_workers, len(tasks))

    def worker():
        sb = None
        thread_id = threading.get_ident()

        while True:
            try:
                task_item = task_queue.get_nowait()
            except queue.Empty:
                break

            if sb is None:
                try:
                    sb = sb_cdp.Chrome(**CHROME_ARGS)
                except Exception as e:
                    print(f"[Worker {thread_id}] 浏览器初始化失败: {e}")
                    task_queue.task_done()
                    continue

            # 10s 强制超时控制
            timer = threading.Timer(
                10.0, lambda: sb.driver.stop() if sb and sb.driver else None
            )
            timer.start()
            start_t = time.time()

            try:
                res = process_task_fn(sb, task_item)
                if res is not None:
                    with results_lock:
                        results.append(res)
            except Exception as e:
                duration = time.time() - start_t
                if duration >= 9.9:
                    print(f"[Worker {thread_id}] 任务强制超时 (10s): {task_item}")
                else:
                    print(f"[Worker {thread_id}] 执行异常: {e}")
                sb = None
            finally:
                timer.cancel()
                task_queue.task_done()

        if sb:
            try:
                sb.driver.stop()
            except Exception:
                pass

    threads = []
    for _ in range(actual_workers):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    task_queue.join()
    return results


# ------------------------------
# FreeProxy World 解析与批量任务
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
            print(f"解析行出错: {e}")
            continue

    return results


def get_total_pages(soup):
    """从分页栏获取最大页码"""
    pagination_div = soup.find("div", class_="pagination")
    if not pagination_div:
        return 1

    page_numbers = []
    for a_tag in pagination_div.find_all("a"):
        text = a_tag.get_text(strip=True)
        if text.isdigit():
            page_numbers.append(int(text))

    return max(page_numbers) if page_numbers else 1


def _fetch_pagemax_task(sb, task):
    """Worker 获取单配置最大页码"""
    name = task["name"]
    url = task["url"]
    config = task["config"]
    try:
        total_pages = fetch_page_with_cdp(sb, url, get_total_pages)
        print(f"[{name}] 最大页码探测成功: {total_pages} 页 ({url})")
        return {"name": name, "config": config, "total_pages": total_pages, "success": True}
    except Exception as e:
        print(f"[{name}] 获取最大页码失败: {e}")
        return {"name": name, "config": config, "url": url, "success": False}


def _fetch_proxies_task(sb, url):
    """Worker 抓取单个页面的代理节点"""
    proxies = fetch_page_with_cdp(sb, url, extract_proxies)
    return [ProxyNode(p) for p in proxies]


def batch_fetch_pagemax(configs, max_workers=8):
    """8 线程并发探测所有配置的最大页码数，支持重试 1 次"""
    tasks = []
    for item in configs:
        name, config = next(iter(item.items()))
        base_url = f"https://www.freeproxy.world/?{urllib.parse.urlencode(config)}"
        tasks.append({"name": name, "config": config, "url": base_url})

    print(f"\n[阶段 1/2] 启动 {min(max_workers, len(tasks))} 线程并发探测各配置最大页码 (共 {len(tasks)} 个配置)...")
    round1_results = run_cdp_task_queue(tasks, _fetch_pagemax_task, max_workers=max_workers)

    successful = {r["name"]: r for r in round1_results if r.get("success")}
    failed_tasks = [t for t in tasks if t["name"] not in successful]

    if failed_tasks:
        print(f"\n[阶段 1/2] 检测到 {len(failed_tasks)} 个配置探测失败，等待 2 秒后进行重试...")
        time.sleep(2)
        round2_results = run_cdp_task_queue(failed_tasks, _fetch_pagemax_task, max_workers=max_workers)
        for r in round2_results:
            if r.get("success"):
                successful[r["name"]] = r

    print(f"[阶段 1/2] 最大页码探测完成，成功: {len(successful)}/{len(tasks)} 个配置。\n")
    return list(successful.values())


def batch_fetch_proxies(urls, max_workers=8):
    """8 线程并发抓取所有目标页面"""
    print(f"\n[阶段 2/2] 启动 {min(max_workers, len(urls))} 线程全局并发抓取全部 {len(urls)} 个目标页面...")
    raw_results = run_cdp_task_queue(urls, _fetch_proxies_task, max_workers=max_workers)
    all_nodes = set()
    for node_list in raw_results:
        all_nodes.update(node_list)
    print(f"[阶段 2/2] 页面抓取完成，共获得 {len(all_nodes)} 个节点。\n")
    return all_nodes


# ------------------------------
# IP 归属地复核与过滤模块 (ip2region)
# ------------------------------
def review_and_filter_proxies(proxy_nodes, allowed_countries, db_path="ip2region_v4.xdb"):
    """
    使用 ip2region 数据库复核代理节点的真实归属地，覆盖 country, city, country_code，
    过滤掉不在 allowed_countries 中的节点，并汇总去重输出被删除节点的国家代码。
    """
    if not os.path.exists(db_path):
        print(f"[ip2region] 提示：未找到本地数据库文件 {db_path}，跳过归属地复核。")
        return proxy_nodes

    try:
        c_buffer = util.load_content_from_file(db_path)
        searcher = xdb.new_with_buffer(util.IPv4, c_buffer)
    except Exception as e:
        print(f"[ip2region] 初始化内存查询对象失败: {e}，跳过归属地复核。")
        return proxy_nodes

    allowed_set = {c.strip().upper() for c in allowed_countries if c and c.strip()}
    filtered_nodes = set()
    dropped_country_codes = set()
    total_count = len(proxy_nodes)
    dropped_count = 0

    print(f"\n[ip2region] 开始对 {total_count} 个节点进行归属地复核 (允许国家: {sorted(allowed_set)})...")

    for node in proxy_nodes:
        ip = node.ip
        region = ""
        try:
            region = searcher.search(ip)
        except Exception:
            pass

        if region:
            parts = region.split("|")
            # ip2region 格式: 国家|省份|城市|ISP|国家代码
            r_country = parts[0] if len(parts) > 0 and parts[0] != "0" else ""
            r_province = parts[1] if len(parts) > 1 and parts[1] != "0" else ""
            r_code = parts[4].upper() if len(parts) > 4 and parts[4] != "0" else ""

            # 获取复核后的国家代码进行过滤判断
            target_code = r_code if r_code else node.all.get("country_code", "").upper()
            if allowed_set and target_code and target_code not in allowed_set:
                dropped_count += 1
                dropped_country_codes.add(target_code)
                continue

            # 覆盖字段信息（省份代替 city）
            if r_country:
                node.all["country"] = r_country
            if r_code:
                node.all["country_code"] = r_code
            node.all["city"] = r_province
        else:
            # 查无结果时，基于原有国家代码做白名单检测
            orig_code = node.all.get("country_code", "").upper()
            if allowed_set and orig_code and orig_code not in allowed_set:
                dropped_count += 1
                dropped_country_codes.add(orig_code)
                continue

        filtered_nodes.add(node)

    print(
        f"[ip2region] 复核完成：共处理 {total_count} 个节点，保留 {len(filtered_nodes)} 个节点，剔除 {dropped_count} 个未在配置列表中的节点。"
    )
    if dropped_country_codes:
        print(f"[ip2region] 剔除节点的国家代码汇总 ({len(dropped_country_codes)} 个): {sorted(dropped_country_codes)}\n")
    else:
        print(f"[ip2region] 未剔除任何国家节点。\n")

    return filtered_nodes


# ------------------------------
# 主执行流程
# ------------------------------
def main():
    config_path = "config.yml"
    with open(config_path, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f)

    freeproxy_only = config_data.get("freeproxy_only", False)
    maxpages = config_data.get("maxpages", 150)
    configs = config_data.get("freeproxy_list", [])

    # 提取配置中所有允许的国家代码
    allowed_countries = set()
    for item in configs:
        for _, cfg in item.items():
            if isinstance(cfg, dict) and "country" in cfg and cfg["country"]:
                allowed_countries.add(str(cfg["country"]).strip().upper())

    all_results = set()

    if freeproxy_only:
        print("[配置] 已开启 freeproxy_only，仅抓取 FreeProxy World 数据源。")
    else:
        print("[配置] 正在加载 ProxyScrape 初始数据源...")
        all_results.update(fetch_proxyscrape())

    # 阶段 1：8 线程并发探测所有配置的最大页码
    pagemax_results = batch_fetch_pagemax(configs, max_workers=8)

    # 聚合生成待抓取 URL
    collected_urls = []
    for item in pagemax_results:
        name = item["name"]
        config = item["config"]
        valid_pagemax = item["total_pages"]
        base_url = f"https://www.freeproxy.world/?{urllib.parse.urlencode(config)}"

        pages_to_fetch = min(valid_pagemax, maxpages)
        pagelist = random.sample(range(1, valid_pagemax + 1), pages_to_fetch)
        print(f"[{name}] 总页数: {valid_pagemax}，计划抓取 {len(pagelist)} 页。")

        for page in pagelist:
            collected_urls.append(f"{base_url}&page={page}")

    # URL 去重（防范重复配置，保持顺序）
    all_target_urls = list(dict.fromkeys(collected_urls))
    print(f"\n[阶段 1/2 完成] 汇总生成 {len(collected_urls)} 个页面请求，去重后共 {len(all_target_urls)} 个待抓取 URL。")

    # 阶段 2：8 线程全局并发抓取所有目标页面
    if all_target_urls:
        freeproxy_results = batch_fetch_proxies(all_target_urls, max_workers=8)
        all_results.update(freeproxy_results)

    # 阶段 3：使用 ip2region 复核真实归属地并按配置国家过滤
    all_results = review_and_filter_proxies(all_results, allowed_countries)

    # 导出保存
    os.makedirs("data", exist_ok=True)

    output = [result.all for result in all_results]
    with open("data/raw.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    with open("data/raw.txt", "w", encoding="utf-8") as f:
        for result in all_results:
            f.write(repr(result) + "\n")

    print(f"==========================================")
    print(f"全部任务完成！最终共导出 {len(output)} 个有效代理节点。")
    print(f"已保存至 data/raw.json 和 data/raw.txt")
    print(f"==========================================")


if __name__ == "__main__":
    main()
