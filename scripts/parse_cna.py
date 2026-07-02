import re
import json
import sys
from collections import defaultdict

input_path = sys.argv[1] if len(sys.argv) > 1 else 'scripts/edr-enum.cna'
with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Extract process signatures
pattern = r'%edr_process_signatures\["([^"]+)"\]\s*=\s*"([^"]+)"'
matches = re.findall(pattern, content)

# Group by vendor/product/category
groups = defaultdict(list)
for proc, info in matches:
    parts = [x.strip() for x in info.split('|')]
    if len(parts) >= 3:
        vendor, product, category = parts[0], parts[1], parts[2]
        groups[(vendor, product, category)].append(proc.lower())

print(f"Total process signatures: {len(matches)}", file=__import__('sys').stderr)
print(f"Unique groups: {len(groups)}", file=__import__('sys').stderr)

# Generate JSON array
rules = []
for (vendor, product, category), procs in sorted(groups.items(), key=lambda x: (x[0][2], x[0][0], x[0][1])):
    escaped_procs = [re.escape(p) for p in procs]
    regex = '(?i)\\b(?:' + '|'.join(escaped_procs) + ')\\b'
    rules.append({
        "name": f"{vendor} {product}",
        "category": category,
        "pattern": regex,
        "processes": procs,
    })

print(json.dumps(rules, indent=2, ensure_ascii=False))
