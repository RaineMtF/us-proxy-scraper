import json
import os
import queue
import random
import re
import threading
import time
import urllib.parse

import requests
import yaml
from bs4 import BeautifulSoup
from seleniumbase import sb_cdp


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
# FreeProxy World 抓取模块
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
RESULTS_LOCK = threading.Lock()


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


def _fetch_pagemax(url, max_retries=1):
    """
    通过 SeleniumBase CDP 获取目标 URL 的最大页码数。
    若失败则等待后重试 max_retries 次，重试仍失败则返回 None。
    """
    for attempt in range(1 + max_retries):
        sb_fp = None
        try:
            if attempt > 0:
                print(f"[Freeproxy CDP] 重试获取最大页码 (第 {attempt} 次重试): {url}")
                time.sleep(2)
            else:
                print(f"[Freeproxy CDP] 开始获取最大页码数: {url}")

            sb_fp = sb_cdp.Chrome(url=url, **CHROME_ARGS)
            bs4_data = sb_fp.get_beautiful_soup()
            if check_anti_bot_status(bs4_data)["is_blocked"]:
                sb_fp.gui_click_captcha()
                bs4_data = sb_fp.get_beautiful_soup()
            total_pages = get_total_pages(bs4_data)
            print(f"[Freeproxy CDP] 最大页码数 {url} 为 {total_pages}")
            return total_pages
        except Exception as e:
            print(f"[Freeproxy CDP] 获取最大页码失败 ({url}, attempt={attempt + 1}): {e}")
        finally:
            if sb_fp:
                try:
                    sb_fp.driver.stop()
                except Exception:
                    pass

    print(f"[Freeproxy CDP] 重试耗尽，获取最大页码失败，跳过该配置: {url}")
    return None


def _worker_process(url_queue, results):
    """多线程 Worker：从队列取页面抓取并提取代理"""
    sb = None
    thread_id = threading.get_ident()

    while True:
        try:
            url = url_queue.get_nowait()
        except queue.Empty:
            break

        if sb is None:
            try:
                print(f"[Worker {thread_id}] 正在初始化浏览器...")
                sb = sb_cdp.Chrome(**CHROME_ARGS)
            except Exception as e:
                print(f"[Worker {thread_id}] 浏览器启动失败: {e}")
                url_queue.task_done()
                continue

        # 10 秒超时强制中断计时器
        timer = threading.Timer(
            10.0, lambda: sb.driver.stop() if sb and sb.driver else None
        )
        timer.start()

        task_start_time = time.time()
        try:
            print(f"[Worker {thread_id}] 正在处理 (限时10s): {url}")
            sb.open(url)
            sb.assert_element("table tr", timeout=5)
            bs4_data = sb.get_beautiful_soup()

            if check_anti_bot_status(bs4_data)["is_blocked"]:
                print(f"[Worker {thread_id}] 检测到验证码，等待鼠标锁...")
                with CAPTCHA_LOCK:
                    print(f"[Worker {thread_id}] 正在点击验证码...")
                    sb.gui_click_captcha()

                sb.assert_element("table tr", timeout=5)
                bs4_data = sb.get_beautiful_soup()

            proxies = extract_proxies(bs4_data)
            with RESULTS_LOCK:
                for proxy in proxies:
                    results.add(ProxyNode(proxy))

            print(
                f"[Worker {thread_id}] 任务成功: {url} (用时: {time.time() - task_start_time:.1f}s)"
            )
        except Exception as e:
            duration = time.time() - task_start_time
            if duration >= 9.9:
                print(f"[Worker {thread_id}] !! 任务强制超时 (10s) 自动终止: {url}")
            else:
                print(f"[Worker {thread_id}] 抓取失败 {url}: {e}")
            sb = None
        finally:
            timer.cancel()
            url_queue.task_done()

    if sb:
        try:
            sb.driver.stop()
        except Exception:
            pass


def _fetch_htmls(urls, max_workers=8):
    """并发抓取调度器：使用 8 线程并发处理所有 URL 队列"""
    if not urls:
        return set()

    url_queue = queue.Queue()
    for url in urls:
        url_queue.put(url)

    results = set()
    actual_workers = min(max_workers, len(urls))
    print(f"\n[调度中心] 启动 {actual_workers} 个并发 worker 抓取全部 {len(urls)} 个目标页面...")

    threads = []
    for _ in range(actual_workers):
        t = threading.Thread(target=_worker_process, args=(url_queue, results))
        t.daemon = True
        t.start()
        threads.append(t)

    url_queue.join()
    print(f"[调度中心] 全部页面抓取任务处理完毕。\n")
    return results


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

    all_results = set()

    if freeproxy_only:
        print("[配置] 已开启 freeproxy_only，仅抓取 FreeProxy World 数据源。")
    else:
        print("[配置] 正在加载 ProxyScrape 初始数据源...")
        all_results.update(fetch_proxyscrape())

    # 阶段 1：单线程逐个获取各配置的最大页码，并聚合生成待抓取 URL
    collected_urls = []
    print(f"\n[阶段 1/2] 开始单线程检测各配置的最大页码数 (共 {len(configs)} 个配置)...")
    for item in configs:
        name, config = next(iter(item.items()))
        base_url = f"https://www.freeproxy.world/?{urllib.parse.urlencode(config)}"
        print(f"[{name}] 正在获取最大页码，配置：{config}")

        valid_pagemax = _fetch_pagemax(base_url, max_retries=1)
        if valid_pagemax is None or valid_pagemax < 1:
            print(f"[{name}] 无法获取有效页码，跳过该配置。")
            continue

        pages_to_fetch = min(valid_pagemax, maxpages)
        pagelist = random.sample(range(1, valid_pagemax + 1), pages_to_fetch)
        print(f"[{name}] 总页数: {valid_pagemax}，计划抓取 {len(pagelist)} 页。")

        for page in pagelist:
            collected_urls.append(f"{base_url}&page={page}")

    # URL 去重（防范重复配置，保持顺序）
    all_target_urls = list(dict.fromkeys(collected_urls))
    print(f"\n[阶段 1/2 完成] 汇总生成 {len(collected_urls)} 个页面请求，去重后共 {len(all_target_urls)} 个待抓取 URL。")

    # 阶段 2：将所有 URL 统一交给 8 线程 Worker 进行全局并发抓取
    if all_target_urls:
        print(f"\n[阶段 2/2] 启动 8 线程全局并发抓取...")
        freeproxy_results = _fetch_htmls(all_target_urls, max_workers=8)
        all_results.update(freeproxy_results)

    # 导出保存
    os.makedirs("data", exist_ok=True)

    output = [result.all for result in all_results]
    with open("data/raw.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    with open("data/raw.txt", "w", encoding="utf-8") as f:
        for result in all_results:
            f.write(repr(result) + "\n")

    print(f"\n==========================================")
    print(f"抓取完成！共获取 {len(output)} 个有效代理节点。")
    print(f"已保存至 data/raw.json 和 data/raw.txt")
    print(f"==========================================")


if __name__ == "__main__":
    main()
