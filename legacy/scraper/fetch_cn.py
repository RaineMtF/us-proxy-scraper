import json
import os
import yaml
import time

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from freeproxy_world_scraper import *

def verify_proxy(proxy_str):
    """
    检测单个代理是否符合“中国节点”特征
    """
    # 替换 SOCKS 协议头部，强制让代理服务器进行 DNS 解析 (Remote DNS)
    # 这对于测试 GFW 的 DNS 污染/阻断至关重要
    if proxy_str.startswith("socks5://"):
        proxy_str = proxy_str.replace("socks5://", "socks5h://", 1)
    elif proxy_str.startswith("socks4://"):
        proxy_str = proxy_str.replace("socks4://", "socks4a://", 1)

    proxies = {"http": proxy_str, "https": proxy_str}

    # 设置一个常见的 User-Agent 防止被直接当作爬虫拦截
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }

    # 第一步：检测百度 (必须在 20s 内返回 200)
    try:
        r_baidu = requests.get(
            "https://www.baidu.com/favicon.ico",
            proxies=proxies,
            headers=headers,
            timeout=10,
        )
        if r_baidu.status_code != 200:
            return None  # 状态码不对，剔除
    except requests.RequestException:
        return None  # 访问百度超时或连接失败，剔除

    # 第二步：检测 YouTube (必须在 20s 内无响应，或状态码不在 [200, 399] 之间)
    try:
        r_youtube = requests.get(
            "https://www.youtube.com/favicon.ico",
            proxies=proxies,
            headers=headers,
            timeout=10,
        )

        # 如果有响应，且状态码在 200 到 399 之间，说明成功访问了 YouTube，说明不是纯正的境内节点
        if 200 <= r_youtube.status_code <= 399:
            return None

    except requests.RequestException:
        # 抛出异常 (Timeout, ConnectionError) 说明被 GFW 墙了，正好符合我们的“中国节点”预期
        pass

    # 两个条件都满足，返回处理后的代理字符串
    return proxy_str


def filter_chinese_proxies(proxy_list, max_threads=20):
    """
    多线程批量检测代理数组
    :param proxy_list: 包含代理URL的原始数组
    :param max_threads: 并发线程数
    :return: 验证合格的代理数组
    """
    valid_proxies = []

    # 使用线程池进行多线程并发检测
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # 提交所有任务
        future_to_proxy = {executor.submit(verify_proxy, p): p for p in proxy_list}

        # 获取结果
        for future in as_completed(future_to_proxy):
            result = future.result()
            if result is not None:
                valid_proxies.append(result)
                print(f"[SUCCESS] 发现合格中国节点: {result}")

    return valid_proxies


def fetch_proxyscrape():
    """
    从 ProxyScrape 获取中国代理节点列表
    请求两个不同的数据源，按行分割、清洗、去重后返回数组
    """
    urls = [
        "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/countries/cn/data.txt",
        "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&country=cn",
    ]

    proxy_list = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    for url in urls:
        try:
            print(f"[ProxyScrape] 正在请求数据源: {url}")
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                # 按行分割，去除首尾空格，并过滤掉空行
                lines = [
                    line.strip() for line in response.text.splitlines() if line.strip()
                ]
                proxy_list.extend(lines)
            else:
                print(f"[ProxyScrape] 请求失败，状态码: {response.status_code}")
        except requests.RequestException as e:
            print(f"[ProxyScrape] 请求网络异常: {e}")

    # 利用 set 去除两个源可能重复的节点
    return list(set(proxy_list))


def fetch_geonode():
    """
    从 Geonode API 分页获取中国代理节点列表
    自动增加 page 进行翻页，直到返回的 data 数组为空。
    返回格式化后的 ['protocol://ip:port', ...] 数组
    """
    base_url = "https://proxylist.geonode.com/api/proxy-list?country=CN&limit=500&sort_by=lastChecked&sort_type=desc"
    proxy_list = []
    page = 1
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    while True:
        url = f"{base_url}&page={page}"
        try:
            print(f"[Geonode] 正在抓取第 {page} 页数据...")
            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code != 200:
                print(f"[Geonode] 请求失败，状态码: {response.status_code}，停止抓取。")
                break

            json_data = response.json()
            data_items = json_data.get("data", [])

            # 如果 data 字段为空列表，说明已经没有更多数据，退出循环
            if not data_items:
                print("[Geonode] 检测到 data 为空，数据已全部抓取完毕。")
                break

            for item in data_items:
                ip = item.get("ip")
                port = item.get("port")
                protocols = item.get("protocols", [])

                if ip and port and protocols:
                    # 取第一个协议类型（例如 'socks5'、'http' 等）
                    protocol = protocols[0]
                    # 组装成您需要的标准格式：protocol://ip:port
                    proxy_str = f"{protocol}://{ip}:{port}"
                    proxy_list.append(proxy_str)

            # 页码 + 1 准备下一次请求
            page += 1

        except requests.RequestException as e:
            print(f"[Geonode] 请求网络异常 (第 {page} 页): {e}")
            break
        except (ValueError, KeyError) as e:
            print(f"[Geonode] 解析 JSON 格式出错 (第 {page} 页): {e}")
            break

    return list(set(proxy_list))


def get_cn():
    config = {"country": "CN"}
    
    cn_exist = []
    if os.path.exists('../data/cn_checked.txt'):
        with open('../data/cn_checked.txt', 'r', encoding='utf-8') as file:
            # 读取所有行并去除每行末尾的换行符
            cn_exist = [line.strip() for line in file.readlines()]

    print("正在抓取 ProxyScrape China 节点")
    proxyscrape_nodes = fetch_proxyscrape()
    print("正在抓取 GeoNode China 节点")
    geonode_nodes = fetch_geonode()
    print("正在抓取 FreeProxyWorld China 节点")
    freeproxy_nodes_raw = fetch_freeproxy_work_pagemax(config, 50)
    freeproxy_nodes = [f"{i.type}://{i.ip}:{i.port}" for i in freeproxy_nodes_raw]

    cn_results = list(set(cn_exist + proxyscrape_nodes + geonode_nodes + freeproxy_nodes))

    print(f"抓取到 {len(cn_results)} 个中国节点")
    with open("../data/cn_raw.txt", "w", encoding="utf-8") as f:
        for result in cn_results:
            f.write(result + "\n")
    print("写入 cn_raw.txt 成功，开始批量检测")
    cn_valid = filter_chinese_proxies(cn_results, max_threads=256)
    with open("../data/cn_checked.txt", "w", encoding="utf-8") as f:
        for result in cn_valid:
            f.write(result + "\n")
    print(f"检测完成，写入 {len(cn_valid)} 个节点，将开始正式任务")
