import urllib.parse

import re
import json
from bs4 import BeautifulSoup
import time
import random

import builtins

import threading
import queue
from concurrent.futures import ThreadPoolExecutor
from seleniumbase import sb_cdp

_PRINT_LOCK = threading.Lock()
# 2. 保存原始的 print 函数，防止无限递归
_original_print = builtins.print


def _thread_safe_print(*args, **kwargs):
    """自定义的线程安全打印函数"""
    with _PRINT_LOCK:
        _original_print(*args, **kwargs)


# 3. 全局替换内置的 print
builtins.print = _thread_safe_print


def check_anti_bot_status(soup):
    """
    检查 BeautifulSoup 对象是否被 Cloudflare 盾或常见的验证码(reCAPTCHA/Turnstile等)拦截。

    :param soup: BeautifulSoup 对象
    :return: dict, 包含是否被拦截(is_blocked)、拦截类型(reason)和细节(detail)
    """
    status = {"is_blocked": False, "reason": None, "detail": None}

    if not soup:
        return status

    # --- 1. 检查页面 Title ---
    title_element = soup.title
    title_text = (
        title_element.string.strip() if title_element and title_element.string else ""
    )

    # Cloudflare 常见拦截/等待页标题
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

    # --- 2. 检查 DOM 元素的 ID 和 Class 特征 ---
    # Cloudflare 专属特征 (通常带有 cf- 前缀)
    if soup.find(id=re.compile(r"^cf-")) or soup.find(class_=re.compile(r"^cf-")):
        # 细分是否为 Cloudflare Turnstile 验证码
        if soup.find(class_="cf-turnstile") or soup.find(id="cf-turnstile"):
            status["is_blocked"] = True
            status["reason"] = "Cloudflare Turnstile Widget"
            status["detail"] = "Found Cloudflare Turnstile challenge box."
            return status

        status["is_blocked"] = True
        status["reason"] = "Cloudflare WAF / Challenge"
        status["detail"] = "Found elements with 'cf-' prefix."
        return status

    # reCAPTCHA 特征 (对应可能误写的 rChapter)
    if (
        soup.find(class_="g-recaptcha")
        or soup.find(id="g-recaptcha")
        or soup.find(class_=re.compile(r"recaptcha", re.I))
    ):
        status["is_blocked"] = True
        status["reason"] = "reCAPTCHA"
        status["detail"] = "Found Google reCAPTCHA widget."
        return status

    # hCaptcha 特征 (另一种常见验证码)
    if soup.find(class_="h-captcha") or soup.find(id="h-captcha"):
        status["is_blocked"] = True
        status["reason"] = "hCaptcha"
        status["detail"] = "Found hCaptcha widget."
        return status

    # --- 3. 检查外部脚本链接 (Script Sources) ---
    scripts = soup.find_all("script", src=True)
    for script in scripts:
        src = script["src"].lower()
        if "recaptcha" in src:
            status["is_blocked"] = True
            status["reason"] = "reCAPTCHA (Script)"
            status["detail"] = f"Loaded reCAPTCHA script: {src}"
            return status
        if "cloudflare" in src and "turnstile" in src:
            status["is_blocked"] = True
            status["reason"] = "Cloudflare Turnstile (Script)"
            status["detail"] = f"Loaded Turnstile script: {src}"
            return status
        if "hcaptcha" in src:
            status["is_blocked"] = True
            status["reason"] = "hCaptcha (Script)"
            status["detail"] = f"Loaded hCaptcha script: {src}"
            return status

    # --- 4. 检查页面特定文本特征 (WAF 错误码与特征词) ---
    body_text = soup.get_text().lower()
    if "error code: 1020" in body_text:
        status["is_blocked"] = True
        status["reason"] = "Cloudflare WAF Block (Error 1020)"
        status["detail"] = "Your IP or request signature was explicitly denied by CF."
        return status
    if (
        "checking your browser before accessing" in body_text
        or "enable cookies" in body_text
    ):
        if "cloudflare" in body_text:
            status["is_blocked"] = True
            status["reason"] = "Cloudflare IUAM"
            status["detail"] = "Under Attack Mode (5-second browser verification)."
            return status

    return status


def extract_proxies(soup):
    results = []
    trs = soup.find_all("tr")
    for tr in trs:
        tds = tr.find_all("td")
        if len(tds) < 7:
            continue
        try:
            proxy_type = tds[5].get_text(separator=" ", strip=True).split(" ")
            best_type = proxy_type[-1]

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
                "type_list": proxy_type,
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
    """
    从 BeautifulSoup 对象中提取最大页码数。

    :param soup: BeautifulSoup 对象
    :return: 最大页码数（整型），如果未找到则返回 1
    """
    # 定位到分页的 div
    pagination_div = soup.find("div", class_="pagination")
    if not pagination_div:
        return 1

    page_numbers = []

    # 遍历所有的 <a> 标签
    for a_tag in pagination_div.find_all("a"):
        text = a_tag.get_text(strip=True)
        # 过滤出纯数字的页码，排除 '»' 等非数字符号
        if text.isdigit():
            page_numbers.append(int(text))

    # 返回最大页码，若无有效页码则默认返回 1
    total_pages = max(page_numbers) if page_numbers else 1
    return total_pages


class ProxyNode:
    def __init__(self, data):
        self.ip = data["ip"]
        self.port = data["port"]
        self.type = data["type"]
        # 可以根据需要保留其他属性
        self.all = data

    def __hash__(self):
        # 使用 ip, port, type 的元组生成哈希值
        return hash((self.ip, self.port, self.type))

    def __eq__(self, other):
        # 必须同时定义相等性逻辑，确保哈希碰撞时能正确处理
        if not isinstance(other, ProxyNode):
            return False
        return (self.ip, self.port, self.type) == (other.ip, other.port, other.type)

    def __repr__(self):
        # return json.dumps(self.all, ensure_ascii=False)
        name = urllib.parse.quote(
            f"{self.all['country_code']} {self.type.upper()}"
            + f" ({self.all['city']}, {self.all['country']}) "
            + f"{self.ip}:{self.port}"
        )
        return f"{self.type}://{self.ip}:{self.port}#{name}"


BLOCKED_URLS = [
    # 静态资源
    "*.js",
    "*.css",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.svg",
    "*.ico",
    "*.bmp",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.otf",
    "*.eot",
    # 多媒体
    "*.mp4",
    "*.mp3",
    "*.wav",
    "*.webm",
    # 广告 & 追踪 (更全面)
    "*doubleclick*",
    "*googletagmanager*",
    "*google-analytics*",  # ← 原版遗漏
    "*googlesyndication*",  # ← 原版遗漏
    "*connect.facebook*",  # ← 原版遗漏
    "*ads*",
    "*cloudflareinsights*",
    "*analytics*",
    "*tracking*",  # ← 原版遗漏
    "*hotjar*",  # ← 原版遗漏
    "*sentry*",  # ← 原版遗漏
    # 第三方 CDN (样式/组件)
    "*cdn.jsdelivr.net*",
    "*cdnjs.cloudflare.com/ajax*",
]

CHROMIUM_ARGS = [
    "--disable-gpu",  # 禁用 GPU 硬件加速，在无头模式下可避免部分环境崩溃并提升渲染速度
    "--disable-dev-shm-usage",  # 解决 Docker 或 Linux 环境下共享内存不足导致崩溃的问题
    "--no-sandbox",  # 禁用沙盒模式（Root权限运行必须，且能减少沙盒初始化的性能开销）
    "--disable-extensions",  # 禁用所有 Chrome 扩展程序，大幅加快启动速度
    "--disable-setuid-sandbox",  # 配合 no-sandbox 使用
    "--mute-audio",  # 禁用音频，节省音频解码的 CPU 开销
    "--disable-notifications",  # 禁用浏览器桌面通知
    "--disable-web-security",  # 禁用同源策略（可选，用于跨域抓取）
    "--no-first-run",  # 跳过首次运行检查，节约首次启动时间
    "--no-zygote",  # 禁用zygote进程，减少进程创建时间（部分场景有效）
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


def _fetch_pagemax(url):
    sb_fp = sb_cdp.Chrome(url=url, **CHROME_ARGS)
    # sb_fp.driver.execute_cdp_cmd("Network.enable", {})
    # sb_fp.driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": BLOCKED_URLS})
    # Pure CDP 不支持 Driver 的操作
    try:
        print(f"[Freeproxy CDP] 开始获取最大页码数: {url}")
        bs4_data = sb_fp.get_beautiful_soup()
        if check_anti_bot_status(bs4_data)["is_blocked"]:
            sb_fp.gui_click_captcha()
            bs4_data = sb_fp.get_beautiful_soup()
        total_pages = get_total_pages(bs4_data)
        print(f"[Freeproxy CDP] 最大页码数 {url} 为 {total_pages}")
        return total_pages
    except Exception as e:
        raise ValueError(f"[Freeproxy CDP] 获取最大页码失败: {e}")
    finally:
        # Pure CDP 模式中，不要忘了执行 stop 来清理释放后台浏览器进程
        sb_fp.driver.stop()


CAPTCHA_LOCK = threading.Lock()  # 保护鼠标点击
RESULTS_LOCK = threading.Lock()  # 保护结果集


def _worker_process(url_queue, results):
    """
    单个 worker 线程
    """
    sb = None
    thread_id = threading.get_ident()

    while True:
        try:
            # 1. 获取任务
            url = url_queue.get_nowait()
        except queue.Empty:
            break

        # 2. 确保当前线程有可用的浏览器实例
        if sb is None:
            try:
                print(f"[Worker {thread_id}] 正在初始化浏览器...")
                sb = sb_cdp.Chrome(**CHROME_ARGS)
            except Exception as e:
                print(f"[Worker {thread_id}] 浏览器启动失败: {e}")
                url_queue.task_done()
                continue

        # --- [关键步骤] 设置 10 秒强制超时计时器 ---
        # 如果 10 秒内没执行完，执行 sb.driver.stop() 强制关掉驱动，阻塞的操作会立即崩掉并抛出异常
        timer = threading.Timer(
            10.0, lambda: sb.driver.stop() if sb and sb.driver else None
        )
        timer.start()

        task_start_time = time.time()
        try:
            print(f"[Worker {thread_id}] 正在处理 (限时10s): {url}")

            # 执行具体抓取逻辑
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
            # 如果是超时触发的，这里通常会捕获到 ConnectionClosed 或类似的驱动关闭异常
            duration = time.time() - task_start_time
            if duration >= 9.9:
                print(f"[Worker {thread_id}] !! 任务强制超时 (10s) 自动终止: {url}")
            else:
                print(f"[Worker {thread_id}] 抓取失败 {url}: {e}")

            # 超时或异常后，浏览器可能已经关闭或状态异常，标记为 None 下次循环重新初始化
            sb = None

        finally:
            timer.cancel()  # 任务结束（无论成功失败）务必取消计时器
            url_queue.task_done()

    # 退出线程前清理资源
    if sb:
        try:
            sb.driver.stop()
        except:
            pass


def _fetch_htmls(urls):
    """
    并发抓取调度器
    """
    if not urls:
        return set()

    url_queue = queue.Queue()
    for url in urls:
        url_queue.put(url)

    results = set()

    # 建议：如果 10s 超时很硬，并发数不宜过高，避免系统由于启动多个 Chrome 瞬间卡死
    max_workers = 4
    print(f"\n[调度中心] 启动 {max_workers} 个并发 worker，监控 10s 超时...")

    threads = []
    for i in range(max_workers):
        t = threading.Thread(target=_worker_process, args=(url_queue, results))
        t.daemon = True  # 设置为守护线程，主程序退出时自动销毁
        t.start()
        threads.append(t)

    # 等待队列中的所有任务完成
    url_queue.join()

    # 也可以选择 join 线程
    # for t in threads:
    #     # 这里不需要 join，因为 queue.join() 已经保证任务做完了
    #     pass

    print(f"\n[调度中心] 所有任务处理完毕。")
    return results


def fetch_freeproxy_world(configs):
    urls = []
    for config in configs:
        args = urllib.parse.urlencode(config)
        urls.append(f"https://www.freeproxy.world/?{args}")
    return _fetch_htmls(urls)


def fetch_freeproxy_work_pagelist(config, pagelist):
    urls = []
    args = urllib.parse.urlencode(config)
    for page in pagelist:
        urls.append(f"https://www.freeproxy.world/?{args}&page={page}")
    return _fetch_htmls(urls)


def fetch_freeproxy_work_pagemax(config, pagemax):
    valid_pagemax = _fetch_pagemax(
        f"https://www.freeproxy.world/?{urllib.parse.urlencode(config)}"
    )
    return fetch_freeproxy_work_pagelist(
        config, range(1, min(pagemax, valid_pagemax) + 1)
    )


def fetch_freeproxy_work_pagerandom(config, pagemax):
    valid_pagemax = _fetch_pagemax(
        f"https://www.freeproxy.world/?{urllib.parse.urlencode(config)}"
    )
    pagelist = random.sample(range(1, valid_pagemax + 1), min(valid_pagemax, pagemax))
    return fetch_freeproxy_work_pagelist(config, pagelist)


# if __name__ == "__main__":
# answer = fetch_freeproxy_work_pagerandom({"speed": 5000}, 200)

# with open("data.json", "w", encoding="utf-8") as f:
#     json.dump(answer, f, indent=4, ensure_ascii=False)

# print(_fetch_pagemax('https://www.freeproxy.world/?type=&anonymity=&country=&speed=&port='))

# 测试 fetch_htmls 接口
# test_urls = [
#     "https://www.freeproxy.world/?type=&anonymity=4&country=RO&speed=5000&port=",
#     "https://www.freeproxy.world/?type=&anonymity=4&country=DE&speed=5000&port=",
# ]

# print("=" * 60)
# print("测试 fetch_htmls 接口")
# print("=" * 60)

# htmls = _fetch_htmls(test_urls)

# print("\n" + "=" * 60)
# print(f"成功获取 {len(htmls)} 个页面")
# for i, (url, html) in enumerate(zip(test_urls, htmls), 1):
#     status = "成功" if html else "失败"
#     length = len(html) if html else 0
#     print(f"  [{i}] {url} -> {status} (HTML长度: {length})")
# print("=" * 60)

# with open('data.json', 'w', encoding='utf-8') as f:
# indent=4 用于美化输出（缩进4格）
# ensure_ascii=False 确保中文字符正常显示
# json.dump(htmls, f, indent=4, ensure_ascii=False)
