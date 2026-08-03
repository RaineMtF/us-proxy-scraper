import json
import os
import yaml
import time

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from freeproxy_world_scraper import ProxyNode

import pycountry

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


def fetch_proxyscrape1():
    """
    从 ProxyScrape 获取中国代理节点列表
    请求两个不同的数据源，按行分割、清洗、去重后返回数组
    """
    proxy_list = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        print(f"[ProxyScrape] 正在请求数据源")
        response = requests.get(
            "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/countries/us/socks5/data.json",
            headers=headers, timeout=15)
        
        if response.status_code != 200:
            print(f"[ProxyScrape] 请求失败，状态码: {response.status_code}，停止抓取。")
            return []

        data_items = response.json()
        if not data_items:
            print("[ProxyScrape] 检测到 data 为空，数据已全部抓取完毕。")
            return []
        
        
        for item in data_items:
            # if item.get("uptime_percent") < 60:
            #     pass
            if item.get(item.get("responseTime"), 10000) > 5000:
                pass
            proxy_data = {
                "ip": item.get("ip"),
                "port": item.get("port"),
                "type": item.get("protocol"),
                "type_list": [item.get("protocol")],
                "country": item.get("country"),
                "country_code": item.get("country_code"),
                "city": item.get("city"),
                "delay": item.get("responseTime"),
                "anonymity": item.get("latency_ms"),
            }
            
            proxy_list.add(ProxyNode(proxy_data))

    except requests.RequestException as e:
        print(f"[ProxyScrape] 请求网络异常: {e}")

    # 利用 set 去除两个源可能重复的节点
    return proxy_list



def fetch_proxyscrape2():
    """
    从 ProxyScrape 获取中国代理节点列表
    请求两个不同的数据源，按行分割、清洗、去重后返回数组
    """
    proxy_list = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        print(f"[ProxyScrape] 正在请求数据源")
        response = requests.get(
            "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/countries/us/socks4/data.json",
            headers=headers, timeout=15)
        
        if response.status_code != 200:
            print(f"[ProxyScrape] 请求失败，状态码: {response.status_code}，停止抓取。")
            return []

        data_items = response.json()
        if not data_items:
            print("[ProxyScrape] 检测到 data 为空，数据已全部抓取完毕。")
            return []
        
        
        for item in data_items:
            # if item.get("uptime_percent") < 60:
            #     pass
            if item.get(item.get("responseTime"), 10000) > 5000:
                pass
            proxy_data = {
                "ip": item.get("ip"),
                "port": item.get("port"),
                "type": item.get("protocol"),
                "type_list": [item.get("protocol")],
                "country": item.get("country"),
                "country_code": item.get("country_code"),
                "city": item.get("city"),
                "delay": item.get("responseTime"),
                "anonymity": item.get("latency_ms"),
            }
            
            proxy_list.add(ProxyNode(proxy_data))

    except requests.RequestException as e:
        print(f"[ProxyScrape] 请求网络异常: {e}")

    # 利用 set 去除两个源可能重复的节点
    return proxy_list

def fetch_geonode():
    """
    从 Geonode API 分页获取中国代理节点列表
    自动增加 page 进行翻页，直到返回的 data 数组为空。
    返回格式化后的 ['protocol://ip:port', ...] 数组
    """
    base_url = "https://proxylist.geonode.com/api/proxy-list?limit=500&sort_by=lastChecked&sort_type=desc"
    proxy_list = set()
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
                return []

            json_data = response.json()
            data_items = json_data.get("data", [])

            # 如果 data 字段为空列表，说明已经没有更多数据，退出循环
            if not data_items:
                print("[Geonode] 检测到 data 为空，数据已全部抓取完毕。")
                return []

            for item in data_items:
                if item.get("responseTime", 10000) > 5000:
                    pass
                
                country_data = pycountry.countries.get(alpha_2=item.get("country"))
                proxy_data = {
                    "ip": item.get("ip"),
                    "port": item.get("port"),
                    "type": item.get("protocols")[-1],
                    "type_list": item.get("protocols"),
                    "country": getattr(country_data, 'name', '') or '',
                    "country_code": item.get("country"),
                    "city": item.get("city"),
                    "delay": item.get("responseTime"),
                    "anonymity": item.get("anonymityLevel"),
                }
                
                proxy_list.add(ProxyNode(proxy_data))

            # 页码 + 1 准备下一次请求
            page += 1

        except requests.RequestException as e:
            print(f"[Geonode] 请求网络异常 (第 {page} 页): {e}")
            return []
        except (ValueError, KeyError) as e:
            print(f"[Geonode] 解析 JSON 格式出错 (第 {page} 页): {e}")
            return []

    return proxy_list


def get_other():
    results = set()
    print("正在抓取 ProxyScrape 1 节点")
    results.update(fetch_proxyscrape1())
    print("正在抓取 ProxyScrape 2 节点")
    results.update(fetch_proxyscrape2())
    # print("正在抓取 GeoNode 节点")
    # results.update(fetch_geonode())
    print(f"抓到 {len(results)} 个其他节点")
    return results
