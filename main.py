import os
import requests
import subprocess
import json

# GitHub Action 中的工作目录
OUTPUT_DIR = "rule-set"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 下载链接
url = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
raw_file_path = os.path.join(OUTPUT_DIR, "filter.txt")
srs_file_path = os.path.join(OUTPUT_DIR, "filter.srs")

# 分流域名规则链接（以 Clash 或 Sing-box 格式为主）
routing_urls = {
    # 可添加实际的分流规则源
    # "cn-sites": "https://example.com/routing.txt",
    "github": "https://raw.githubusercontent.com/SagerNet/sing-geosite/refs/heads/rule-set/geosite-github.srs",
    "openai": "https://raw.githubusercontent.com/SagerNet/sing-geosite/refs/heads/rule-set/geosite-openai.srs",
}

# 路由分流IP规则链接（以 Clash 或 Sing-box 格式为主）
routing_ip = {
    "telegram": "https://github.com/Loyalsoldier/geoip/raw/refs/heads/release/srs/telegram.srs",
    "netfilx": "https://github.com/Loyalsoldier/geoip/raw/refs/heads/release/srs/netflix.srs",
    "google": "https://github.com/Loyalsoldier/geoip/raw/refs/heads/release/srs/google.srs",
    "twitter": "https://github.com/Loyalsoldier/geoip/raw/refs/heads/release/srs/twitter.srs",
}


# 下载过滤器文件并保存到指定路径
def download_filter():
    print("Downloading filter...")
    response = requests.get(url)
    response.raise_for_status()
    with open(raw_file_path, "w", encoding="utf-8") as f:
        f.write(response.text)
    print("Filter downloaded successfully.")


# 使用 sing-box 将过滤器文件转换为 SRS 格式
def convert_with_sing_box():
    print("Converting with sing-box...")
    result = subprocess.run(
        [
            "sing-box",
            "rule-set",
            "convert",
            "--type",
            "adguard",
            "--output",
            srs_file_path,
            raw_file_path,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("Conversion failed:")
        print(result.stderr)
        raise RuntimeError("sing-box conversion failed")
    print("Conversion completed successfully.")


def decompile_srs_to_json(srs_path, json_path):
    print(f"Decompiling {srs_path} to JSON...")
    result = subprocess.run(
        ["sing-box", "rule-set", "decompile", srs_path, "-o", json_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Routing decompilation failed for {srs_path}:\n{result.stderr}"
        )


def compile_json_to_srs(json_path, srs_path):
    print(f"Recompiling {json_path} to {srs_path}...")
    result = subprocess.run(
        ["sing-box", "rule-set", "compile", json_path, "-o", srs_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Recompile failed for {json_path}:\n{result.stderr}")
    print(f"{json_path} successfully recompiled to .srs.")


# 处理路由规则，包括下载、编译为 SRS 格式和反编译为 JSON 格式
def process_routing_rule(name, url):
    compiled_srs = os.path.join(OUTPUT_DIR, f"{name}.srs")
    json_path = os.path.join(OUTPUT_DIR, f"{name}.json")

    print(f"Downloading routing rule {name} from {url}...")

    response = requests.get(url)
    response.raise_for_status()

    # 如果是 .srs 文件，直接保存
    if url.endswith(".srs"):
        with open(compiled_srs, "wb") as f:
            f.write(response.content)

    decompile_srs_to_json(compiled_srs, json_path)
    # compile_json_to_srs(json_path, compiled_srs)

    print(f"{name} routing rule processed.")


# 合并所有路由 JSON 文件为一个文件（合并相同字段，去重值）
def merge_routing_json(output_file, input_prefixes):
    print("Merging all routing JSON files (merged by key)...")
    merged_version = None
    merged_rules = {}

    for prefix in input_prefixes:
        for file in os.listdir(OUTPUT_DIR):
            if file.endswith(".json") and file.startswith(prefix):
                path = os.path.join(OUTPUT_DIR, file)
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if merged_version is None:
                        merged_version = data.get("version")
                    rules = data if isinstance(data, list) else data.get("rules", [])
                    for rule in rules:
                        if not isinstance(rule, dict):
                            continue  # 跳过非法规则结构

                        for key, value in rule.items():
                            if not value:
                                continue  # 跳过空字段

                            if key not in merged_rules:
                                merged_rules[key] = set()

                            if isinstance(value, list):
                                merged_rules[key].update(value)
                            else:
                                merged_rules[key].add(value)

    # 转换为最终格式
    merged = {key: sorted(list(values)) for key, values in merged_rules.items()}
    final = {
        "version": merged_version if merged_version is not None else 1,
        "rules": [merged],
    }
    with open(os.path.join(OUTPUT_DIR, output_file), "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=2)

    print(f"Merged routing JSON saved to {output_file}")


if __name__ == "__main__":
    # 下载过滤器文件
    download_filter()
    # 将过滤器文件转换为 SRS 格式
    convert_with_sing_box()

    # 清理旧的中间 JSON 文件
    for file in os.listdir(OUTPUT_DIR):
        if (
            file.endswith(".json")
            and not file.startswith("filter")
            and file != "merged-routing.json"
        ):
            os.remove(os.path.join(OUTPUT_DIR, file))

    # 处理每个路由规则
    for name, url in routing_urls.items():
        process_routing_rule(name, url)

    for name, ips in routing_ip.items():
        process_routing_rule(name, ips)

    # 合并 routing_urls
    merge_routing_json("merged-domain.json", list(routing_urls.keys()))
    compile_json_to_srs(
        os.path.join(OUTPUT_DIR, "merged-domain.json"),
        os.path.join(OUTPUT_DIR, "merged-domain.srs"),
    )

    # 合并 routing_ip
    merge_routing_json("merged-ip.json", list(routing_ip.keys()))
    compile_json_to_srs(
        os.path.join(OUTPUT_DIR, "merged-ip.json"),
        os.path.join(OUTPUT_DIR, "merged-ip.srs"),
    )

    # 清理中间生成的 JSON 文件，仅保留合并后的文件
    for file in os.listdir(OUTPUT_DIR):
        if (
            file.endswith(".json")
            and not file.startswith("filter")
            and file != "merged-domain.json"
            and file != "merged-ip.json"
        ):
            os.remove(os.path.join(OUTPUT_DIR, file))
