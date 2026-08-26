import json
import os
import yaml
import time

# from fetch_cn import get_cn
from fetch_other import get_other
from freeproxy_world_scraper import *


def main():
    # get_cn()

    with open("../config.yml", "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f)

    print(config_data)

    configs = config_data["freeproxy_list"]
    all_results = get_other()

    # all_results = set()

    for item in configs:
        name, config = next(iter(item.items()))
        print(f"[{name}] 正在抓取配置：{config}")
        try:
            results = fetch_freeproxy_work_pagerandom(config, config_data["maxpages"])
            all_results.update(results)
            print(f"[{name}] 抓取成功，当前共 {len(all_results)} 个不同的节点。")
        except Exception as e:
            print(f"[{name}] 执行时发生错误: {e}, 已跳过继续下一个。")

    # 保存先フォルダ（data）が存在しない場合は自動作成する
    os.makedirs("../data", exist_ok=True)

    output = [result.all for result in all_results]
    with open("../data/raw.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    # 使用 __repr__ 格式写入 raw.txt，每行一个代理节点
    with open("../data/raw.txt", "w", encoding="utf-8") as f:
        for result in all_results:
            f.write(repr(result) + "\n")

    print(f"共获取 {len(output)} 个代理节点，已保存至 data/raw.json 和 data/raw.txt")


if __name__ == "__main__":
    main()
