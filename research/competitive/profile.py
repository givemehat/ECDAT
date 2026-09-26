"""Print a compact profile of each fetched README: first heading, feature bullets, and any
accuracy/latency/CBOM claims. Keeps the manual analysis grounded without reading 300 KB of prose.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "raw_readme")

INTEREST = re.compile(
    r"(cyclonedx\s*1?\.\d|precision|recall|accuracy|false positive|benchmark|mosca|X\s*\+\s*Y|"
    r"harvest now|store now|ml-kem|kyber|ml-dsa|dilithium|sphincs|slh-dsa|fips\s*20[345]|"
    r"nist ir 8547|cnsa|container|oci|docker|binary|elf|pe\b|manifest|dependency|"
    r"gui|dashboard|web ui|fastapi|streamlit|flask|next\.js|semgrep|tree-sitter)",
    re.I)

for name in sorted(os.listdir(SRC)):
    if not name.endswith(".md"):
        continue
    text = open(os.path.join(SRC, name), encoding="utf-8").read()
    if text.startswith("<<README"):
        continue
    print("=" * 100)
    print(name.replace("__", "/").replace(".md", ""))
    head = text.lstrip().splitlines()[:3]
    for line in head:
        if line.strip().startswith("#"):
            print("  " + line.strip()[:110])
            break
    bullets = [b.strip() for b in re.findall(r"^\s*[-*]\s+(.{10,150})", text, re.M)]
    seen = set()
    picks = []
    for b in bullets:
        key = b[:60].lower()
        if key in seen:
            continue
        seen.add(key)
        if INTEREST.search(b):
            picks.append(b)
    for b in picks[:9]:
        print("   - " + re.sub(r"\s+", " ", b)[:140])
    nums = set(re.findall(r"[^.\n]{0,60}\b\d{1,3}\.\d{2,3}\s*%[^.\n]{0,40}", text))
    if nums:
        for n in list(nums)[:4]:
            print("   * " + re.sub(r"\s+", " ", n.strip())[:120])
