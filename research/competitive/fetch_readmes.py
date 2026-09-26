"""Fetch README text for the shortlisted repos so the analysis quotes real behaviour, not
description blurbs. Raw responses land in raw_readme/ and are committed, so every claim in
ANALYSIS.md is checkable offline.

    python fetch_readmes.py
"""
import base64
import json
import os
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "raw_readme")
UA = {"User-Agent": "ecdat-competitive-research", "Accept": "application/vnd.github+json"}

# Ordered by relevance to SIH26164. The first two are sibling teams on the same statement.
TARGETS = [
    "saitharunpotluri-creator/ECDAT",
    "sgtsujith141-wq/cryptodrishti",
    "XiantingWu/PQCensus",
    "CipherIQ/cbom-generator",
    "mpaymenremora/QuantumSeal",
    "chuangtian/QuantumSeal",
    "qubitac/AC-Scanner",
    "csnp/cryptodeps",
    "PQCWorld/pqaudit",
    "jimbo111/open-quantum-secure",
    "Savaid-Khan-Official/Quantum-Migration-Toolkit",
    "Arpan0995/pqc-migration-readiness",
    "SiteQ8/miftah",
    "systemslibrarian/crypto-lab-harvest-timeline",
    "AbstractionsLab/pqc-mat",
    "quantakrypto/pqc-tools",
    "Danny-397/Quantum-Safe-Scan",
]


def get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def main():
    os.makedirs(OUT, exist_ok=True)
    index = {}
    for repo in TARGETS:
        slug = repo.replace("/", "__")
        try:
            raw = json.loads(get(f"https://api.github.com/repos/{repo}").decode("utf-8"))
        except Exception as exc:                                  # noqa: BLE001
            print(f"[!] {repo}: {exc}")
            time.sleep(2)
            continue
        try:
            rdm = json.loads(get(f"https://api.github.com/repos/{repo}/readme").decode("utf-8"))
            text = base64.b64decode(rdm["content"]).decode("utf-8", errors="replace")
        except Exception as exc:                                  # noqa: BLE001
            text = f"<<README unavailable: {exc}>>"
        with open(os.path.join(OUT, f"{slug}.md"), "w", encoding="utf-8") as fh:
            fh.write(text)
        index[repo] = {
            "stars": raw.get("stargazers_count"),
            "forks": raw.get("forks_count"),
            "language": raw.get("language"),
            "license": (raw.get("license") or {}).get("spdx_id"),
            "created_at": raw.get("created_at"),
            "pushed_at": raw.get("pushed_at"),
            "size_kb": raw.get("size"),
            "topics": raw.get("topics"),
            "readme_chars": len(text),
        }
        print(f"[+] {repo:<46} {raw.get('stargazers_count'):>5}*  readme={len(text)}")
        time.sleep(2)

    with open(os.path.join(HERE, "repos.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)
    print(f"\n{len(index)} repo metadata -> repos.json")


if __name__ == "__main__":
    main()
