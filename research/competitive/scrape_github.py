"""Scrape the GitHub search API for projects competing on SIH26164 (IndraMesh).

Scope: cryptographic bill of materials, post-quantum crypto discovery/migration tooling,
quantum risk assessment, and CBOM generation. Raw JSON is written to raw/ so every claim in the
analysis is traceable to a specific API response, and is re-runnable.

    python scrape_github.py            # writes raw/*.json + inventory.csv
"""
import csv
import json
import os
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
UA = {"User-Agent": "indramesh-competitive-research",
      "Accept": "application/vnd.github+json"}
API = "https://api.github.com/search/repositories"

# Each query targets one slice of the competitive space defined in Phase 1 §3/§5.
#
# NOTE: the GitHub *repository* search API does NOT support parentheses or boolean OR -- terms
# are AND-ed and `(a OR b)` silently degrades to a near-unfiltered search (a first attempt
# returned DeFiHackLabs and an IoT list for a "Mosca AND quantum" query). So every query below
# is a single well-formed conjunction, and coverage comes from many narrow queries plus
# `topic:` qualifiers rather than from OR.
QUERIES = {
    "topic_cbom": "topic:cbom",
    "topic_cryptobom": "topic:cryptographic-bill-of-materials",
    "topic_crypto_bom": "topic:crypto-bom",
    "topic_pqc": "topic:pqc",
    "topic_pqc_migration": "topic:pqc-migration",
    "topic_post_quantum": "topic:post-quantum-cryptography",
    "topic_quantum_safe": "topic:quantum-safe",
    "topic_quantum_resistant": "topic:quantum-resistant",
    "topic_cyclonedx": "topic:cyclonedx",
    "topic_cryptography_tools": "topic:cryptography-tools",
    "name_cbom": "cbom in:name",
    "name_crypto_bom": "cryptographic-bill-of-materials in:name",
    "desc_pqc_migration": "post-quantum migration in:description",
    "desc_pq_migration": "PQC migration in:description",
    "desc_quantum_risk": "quantum risk assessment in:description",
    "desc_crypto_discovery": "cryptographic discovery in:description",
    "desc_crypto_inventory": "cryptography inventory in:description",
    "desc_hndl": "harvest now decrypt later in:description",
    "desc_mosca": "Mosca inequality in:description",
    "desc_readiness": "post-quantum readiness in:description",
    "readme_mosca": "Mosca inequality in:readme",
    "readme_hndl": "harvest now decrypt later in:readme",
    "readme_cbom": "cryptographic bill of materials in:readme",
}


FIELDS = ["full_name", "html_url", "description", "language", "stargazers_count",
          "forks_count", "open_issues_count", "created_at", "pushed_at", "license",
          "topics", "archived", "fork", "default_branch", "size"]


def fetch(query, per_page=30):
    url = "{}?q={}&sort=stars&order=desc&per_page={}".format(
        API, urllib.parse.quote(query), per_page)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    os.makedirs(RAW, exist_ok=True)
    seen = {}
    per_query = {}

    for slug, query in QUERIES.items():
        try:
            data = fetch(query)
        except Exception as exc:                      # noqa: BLE001 - report and continue
            print(f"[!] {slug}: {exc}")
            per_query[slug] = {"error": str(exc), "count": 0}
            time.sleep(3)
            continue

        path = os.path.join(RAW, f"{slug}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

        items = data.get("items", [])
        per_query[slug] = {"total_count": data.get("total_count"), "returned": len(items),
                           "query": query}
        print(f"[+] {slug:<20} total={data.get('total_count'):<7} kept={len(items)}")
        for item in items:
            name = item.get("full_name")
            if not name:
                continue
            seen.setdefault(name, {k: item.get(k) for k in FIELDS})
        time.sleep(3)          # stay well inside the unauthenticated search rate limit

    with open(os.path.join(RAW, "_per_query.json"), "w", encoding="utf-8") as fh:
        json.dump(per_query, fh, indent=2)

    rows = []
    for name, meta in sorted(seen.items(), key=lambda kv: -(kv[1].get("stargazers_count") or 0)):
        lic = (meta.get("license") or {}).get("spdx_id") if isinstance(meta.get("license"), dict) else None
        rows.append({
            "repo": name,
            "stars": meta.get("stargazers_count"),
            "forks": meta.get("forks_count"),
            "language": meta.get("language"),
            "license": lic,
            "pushed_at": meta.get("pushed_at"),
            "created_at": meta.get("created_at"),
            "archived": meta.get("archived"),
            "fork": meta.get("fork"),
            "url": meta.get("html_url"),
            "description": (meta.get("description") or "").replace("\n", " ")[:300],
            "topics": ",".join(meta.get("topics") or []),
        })

    with open(os.path.join(HERE, "inventory.csv"), "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["repo"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{len(rows)} unique repositories -> inventory.csv ({len(seen)} seen)")
    print(f"raw responses in {RAW}")


if __name__ == "__main__":
    main()
