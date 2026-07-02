import json
import re
from collections import defaultdict

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def normalize_name(name):
    """统一名称，避免同一个产品出现多个条目"""
    name = name.strip()
    # 移除常见后缀，统一中英文括号
    name = name.replace('（', '(').replace('）', ')')
    return name

def build_regex(processes):
    """把进程列表编译成正则，过滤掉 Linux 路径类进程"""
    valid = []
    for p in processes:
        p = p.strip()
        if not p:
            continue
        # 跳过明显是 Linux 路径的进程（当前 Windows 扫描用 basename 匹配）
        if p.startswith('/'):
            continue
        # 只取 basename
        base = p.replace('\\', '/').split('/')[-1]
        if base:
            valid.append(base.lower())
    if not valid:
        return None
    escaped = [re.escape(p) for p in sorted(set(valid))]
    return '(?i)\\b(?:' + '|'.join(escaped) + ')\\b'

# 加载数据源
av_data = load_json('scripts/antivirus-scan.json')
existing = load_json('assets/process_rules.json')

# 用 name 做索引去重
seen_names = {normalize_name(r['name']): r for r in existing}

# 类别映射：Antivirus-Scan 没有 category，按名称关键词简单分类
def guess_category(name):
    name_lower = name.lower()
    if 'edr' in name_lower or '终端' in name or '天擎' in name or '天珣' in name or 'edr' in name_lower:
        return 'EDR'
    if '防火墙' in name or 'firewall' in name_lower or '云盾' in name or '云安全' in name:
        return 'Firewall/CloudSec'
    if 'agent' in name_lower or '监控' in name or 'assistant' in name_lower or 'tat' in name_lower:
        return 'Agent/Monitor'
    if '杀软' in name or 'antivirus' in name_lower or '安全' in name or 'defender' in name_lower or '卫士' in name or '毒霸' in name:
        return 'AV'
    return 'Security'

added = 0
merged = 0
for raw_name, info in av_data.items():
    name = normalize_name(raw_name)
    processes = info.get('processes', [])
    pattern = build_regex(processes)
    if not pattern:
        continue

    if name in seen_names:
        # 合并进程：把新进程加到已有规则里，重新生成正则
        old_rule = seen_names[name]
        old_procs = set(old_rule.get('processes', []))
        new_procs = []
        for p in processes:
            p = p.strip()
            if p and not p.startswith('/'):
                base = p.replace('\\', '/').split('/')[-1].lower()
                if base not in old_procs:
                    new_procs.append(base)
        if new_procs:
            old_rule['processes'].extend(new_procs)
            old_rule['pattern'] = build_regex(old_rule['processes'])
            merged += len(new_procs)
        continue

    rule = {
        "name": name,
        "category": guess_category(name),
        "pattern": pattern,
        "processes": [p.replace('\\', '/').split('/')[-1].lower() for p in processes if p.strip() and not p.startswith('/')],
    }
    existing.append(rule)
    seen_names[name] = rule
    added += 1

save_json('assets/process_rules.json', existing)
print(f"Added {added} new rules, merged {merged} processes into existing rules.")
print(f"Total rules: {len(existing)}")
