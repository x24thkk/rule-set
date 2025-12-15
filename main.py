import os
import requests
import subprocess
import json

# GitHub Action 中的工作目录
OUTPUT_DIR = "rule-set"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 加载配置文件
CONFIG_FILE = "rules.json"
with open(CONFIG_FILE, "r", encoding="utf-8") as f:
    config = json.load(f)

url = config.get("adguard_filter_url", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
raw_file_path = os.path.join(OUTPUT_DIR, "filter.txt")
srs_file_path = os.path.join(OUTPUT_DIR, "filter.srs")

routing_domain = config.get("routing_domain", {})
routing_ip = config.get("routing_ip", {})

private_url = config.get("private_url",  "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo-lite/geosite/private.srs")
private_srs_file_path = os.path.join(OUTPUT_DIR, "private.srs")

# 下载过滤器文件并保存到指定路径
def download_filter():
    response = requests.get(url)
    response.raise_for_status()
    with open(raw_file_path, "w", encoding="utf-8") as f:
        f.write(response.text)
    print("Filter downloaded successfully.")

def download_private():
    response = requests.get(private_url)
    response.raise_for_status()
    with open(private_srs_file_path, "w", encoding="utf-8") as f:
        f.write(response.text)
    print("private downloaded successfully.")


# 使用 sing-box 将过滤器文件转换为 SRS 格式
def convert_with_sing_box():
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

    # print(f"Downloading routing rule {name} from {url}...")

    response = requests.get(url)
    response.raise_for_status()

    # 如果是 .srs 文件，直接保存
    if url.endswith(".srs"):
        with open(compiled_srs, "wb") as f:
            f.write(response.content)

    decompile_srs_to_json(compiled_srs, json_path)
    # compile_json_to_srs(json_path, compiled_srs)

    count = count_rules_in_json(json_path)
    print(f"{name} routing rule processed, {count} rules.")

    return count


# 合并所有路由 JSON 文件为一个文件（合并相同字段，去重值）
def merge_routing_json(output_file, input_prefixes):
    print("Merging all routing JSON files (merged by key)...")
    merged_version = None
    merged_rules = {}
    total_before = 0  
    file_count = 0

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

                            # 统计合并前的数量
                            if isinstance(value, list):
                                total_before += len(value)
                            else:
                                total_before += 1

                            if key not in merged_rules:
                                merged_rules[key] = set()

                            if isinstance(value, list):
                                merged_rules[key].update(value)
                            else:
                                merged_rules[key].add(value)
                file_count += 1

    merged = {}
    total_after = 0
    for key, values in merged_rules.items():
        original_count = len(values)
        unique_values = sorted(list(values))
        new_count = len(unique_values)
        total_after += new_count
        if original_count != new_count:
            print(
                f'Duplicate detected in key "{key}": {original_count} -> {new_count} after deduplication.'
            )
        merged[key] = unique_values

    final = {
        "version": merged_version if merged_version is not None else 1,
        "rules": [merged],
    }
    output_path = os.path.join(OUTPUT_DIR, output_file)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=2)

    count = count_rules_in_json(output_path)
    print(f"Merge summary: {file_count} input files, {total_before} total entries before dedup, {total_after} after dedup.")
    print(f"Merged routing JSON saved to {output_file}, total {count} rules.")


def process_category(rules_dict, category_name, output_prefix):
    for name, url in rules_dict.items():
        process_routing_rule(name, url)
    
    print(f"Start {category_name} rule merge")
    merged_json = f"merged-{output_prefix}.json"
    merged_srs = f"merged-{output_prefix}.srs"
    merge_routing_json(merged_json, list(rules_dict.keys()))
    compile_json_to_srs(
        os.path.join(OUTPUT_DIR, merged_json),
        os.path.join(OUTPUT_DIR, merged_srs),
    )
    return merged_json, merged_srs


def count_rules_in_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    total = 0
    rules = data if isinstance(data, list) else data.get("rules", [])
    for rule in rules:
        if isinstance(rule, dict):
            for key, value in rule.items():
                if isinstance(value, list):
                    total += len(value)
                elif value: 
                    total += 1
    return total


def export_proxy_lists(ip_json_path, domain_json_path):
    with open(ip_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    ip_list = []
    rules = data.get("rules", [])
    for rule in rules:
        if isinstance(rule, dict):
            ip_list.extend(rule.get("ip_cidr", []))
            ip_list.extend(rule.get("geoip", []))
    proxy_ip_list_path = os.path.join(OUTPUT_DIR, "proxy-ip-list.txt")
    with open(proxy_ip_list_path, "w", encoding="utf-8") as f:
        for ip in sorted(set(ip_list)):
            f.write(f"{ip}\n")
    print(f"Proxy IP list exported to {proxy_ip_list_path}")

    with open(domain_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    domain_list = []
    rules = data.get("rules", [])
    for rule in rules:
        if isinstance(rule, dict):
            for key, values in rule.items():
                if isinstance(values, list):
                    domain_list.extend(values)
    proxy_domain_list_path = os.path.join(OUTPUT_DIR, "proxy-domain-list.txt")
    with open(proxy_domain_list_path, "w", encoding="utf-8") as f:
        for d in sorted(set(domain_list)):
            f.write(f"{d}\n")
    print(f"Proxy domain list exported to {proxy_domain_list_path}")


if __name__ == "__main__":
    for file in os.listdir(OUTPUT_DIR):
        os.remove(os.path.join(OUTPUT_DIR, file))

    download_filter()
    download_private()
    convert_with_sing_box()

    domain_direct_json, domain_direct_srs = process_category(
        routing_domain.get("direct", {}), "domain direct", "domain-direct"
    )
    domain_proxy_json, domain_proxy_srs = process_category(
        routing_domain.get("proxy", {}), "domain proxy", "domain-proxy"
    )
    ip_direct_json, ip_direct_srs = process_category(
        routing_ip.get("direct", {}), "ip direct", "ip-direct"
    )
    ip_proxy_json, ip_proxy_srs = process_category(
        routing_ip.get("proxy", {}), "ip proxy", "ip-proxy"
    )

    export_proxy_lists(
        os.path.join(OUTPUT_DIR, ip_proxy_json),
        os.path.join(OUTPUT_DIR, domain_proxy_json),
    )

    keep_files = {
        "filter.srs",
        "merged-domain-direct.srs",
        "merged-domain-proxy.srs",
        "merged-ip-direct.srs",
        "merged-ip-proxy.srs",
        "merged-domain-direct.json",
        "merged-domain-proxy.json",
        "merged-ip-direct.json",
        "merged-ip-proxy.json",
        "proxy-ip-list.txt",
        "proxy-domain-list.txt",
        "private.srs"
    }
    for file in os.listdir(OUTPUT_DIR):
        if file not in keep_files:
            os.remove(os.path.join(OUTPUT_DIR, file))
