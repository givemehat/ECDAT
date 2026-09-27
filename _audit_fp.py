"""Which NEW rules fire on the Python corpus? Read-only."""
import os, sys, collections
sys.path.insert(0, '.')
from engine.scanner import ECDATScanner

NEW = {"ECD-SRC-JAVA-", "ECD-PHP-", "ECD-RB-"}
root = "benchmark/corpora/paramiko/paramiko"
found = ECDATScanner(enable_ml=False).scan_directory(root)

hits = collections.Counter()
examples = {}
for f in found:
    rid = f.get("rule_id", "")
    if rid.startswith(tuple(NEW)):
        hits[rid] += 1
        examples.setdefault(rid, []).append(
            "%s:%s  %s" % (os.path.basename(f.get("file", "")), f.get("line"), f.get("name")))

print("New-pack rules firing on PYTHON corpus (all should be 0):")
if not hits:
    print("  none")
for rid, n in hits.most_common():
    print("  %-28s %3d  e.g. %s" % (rid, n, examples[rid][0]))

print()
print("Total findings in paramiko:", len(found))
by_rule = collections.Counter(f.get("rule_id") for f in found)
print("Top rules overall:")
for rid, n in by_rule.most_common(8):
    print("  %-28s %3d" % (rid, n))
