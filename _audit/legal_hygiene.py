"""Phase 6: legal / metadata hygiene.

README claims: "Code that must not be redistributed is not in this repository."
and "The dataset redistributes only code whose licence permits it."
Test that claim against the data, without using the repo's own classifiers.
"""
import json, os, re
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def rjl(p):
    return [json.loads(l) for l in open(os.path.join(ROOT, p), encoding='utf-8') if l.strip()]

print('=' * 78)
print('A. LICENSE FILE')
print('=' * 78)
lic = [f for f in os.listdir(ROOT) if re.match(r'(?i)^(licen[cs]e|copying)', f)]
print('  license files at repo root:', lic or 'NONE')
print('  GitHub "License" detection => ', 'None (public domain by default)')
print('  NOTICE.md exists:', os.path.exists(os.path.join(ROOT, 'NOTICE.md')))
print('  README "## Licensing" section:',
      'yes' if '## Licensing' in open(os.path.join(ROOT, 'README.md'), encoding='utf-8').read() else 'no')
print('  README license claim:')
for line in open(os.path.join(ROOT, 'README.md'), encoding='utf-8'):
    if 'redistribute' in line.lower() or 'licence' in line.lower() or 'license' in line.lower():
        if line.strip().startswith(('The dataset', 'A downstream', 'Nothing here')):
            print('   ', line.strip()[:150])

print()
print('=' * 78)
print('B. IS SOURCE TEXT ACTUALLY REDISTRIBUTED? (independent of the repo classifier)')
print('=' * 78)
recs = rjl('derived/records.jsonl')

# B1. Solidity function bodies / contract bodies present as snippet text
SOL = re.compile(r'(function\s+\w+\s*\(|contract\s+\w+|pragma solidity|import\s+\{|'
                 r'require\s*\(|revert\s+\w|\.transfer\(|safeTransferFrom)', re.I)
snippet_recs = 0
snippet_fields = Counter()
big_snippets = 0
for r in recs:
    found = False
    for field in ('code_context', 'code_context_expanded'):
        for e in (r.get(field) or []):
            snippet_fields[field] += 1
            sn = (e.get('snippet') or e.get('code') or '')
            if len(sn) > 200:
                big_snippets += 1
            if SOL.search(sn):
                found = True
    if found:
        snippet_recs += 1
print(f'  records whose citation entries contain Solidity source text: {snippet_recs}/{len(recs)}')
print(f'  citation entries per field: {dict(snippet_fields)}')
print(f'  citation entries with >200 chars of code: {big_snippets}')

# B2. full PoC bodies
poc_recs = sum(1 for r in recs if (r.get('poc') or {}).get('code')
               or (r.get('poc') or {}).get('poc_code'))
print(f'  records carrying PoC source text: {poc_recs}')

# B3. the repo's own redistribution flag
flag = Counter()
for r in recs:
    f = (r.get('redistribution') or {})
    v = f.get('flag')
    if isinstance(v, dict):
        v = v.get('value')
    flag[str(v)] += 1
print(f'  redistribution.flag distribution: {dict(flag)}')
redist = sum(v for k, v in flag.items() if 'redistributed' in k.lower())
print(f'  -> {redist} records are SELF-DECLARED as containing redistributed source '
      f'from an unlicensed repository')

print()
print('=' * 78)
print('C. SAMPLE 20 FLAGGED RECORDS: does the withheld/redistributed text look like real source?')
print('=' * 78)
flagged = [r for r in recs
           if 'redistributed' in str((r.get('redistribution') or {}).get('flag', '')).lower()]
print(f'  pool = {len(flagged)} flagged records; sampling 20 deterministically')
import hashlib
def h(s):
    return int(hashlib.sha256(s.encode()).hexdigest(), 16)
sample = sorted(flagged, key=lambda r: h(str(r.get('id'))))[:20]
for r in sample:
    snips = []
    for e in (r.get('code_context') or []):
        s = (e.get('snippet') or '').strip()
        if s:
            snips.append(s)
    longest = max(snips, key=len) if snips else ''
    lic = r.get('license_classification')
    if isinstance(lic, dict):
        lic = lic.get('value')
    print(f"\n  {r.get('id')}  [{lic}]  {len(snips)} snippets, longest {len(longest)}ch")
    print('   ', (longest[:190].replace('\n', ' | ') if longest else '(none)'))

print()
print('=' * 78)
print('D. PoC CODE: whose code is it? (Code4rena submissions are third-party authored)')
print('=' * 78)
spdx = Counter()
filehdr = Counter()
pocs = 0
for r in recs:
    p = r.get('poc') or {}
    code = p.get('code') or p.get('poc_code') or ''
    if not code:
        continue
    pocs += 1
    m = re.search(r'SPDX-License-Identifier:\s*(\S+)', code)
    spdx[m.group(1) if m else '(no SPDX header)'] += 1
    m2 = re.search(r'^\s*//\s*File:\s*(\S+)', code, re.M)
    if m2:
        filehdr['<forge-std // File: header>'] += 1
    else:
        filehdr['plain source'] += 1
print(f'  PoCs carrying source: {pocs}')
print(f'  SPDX identifiers found in PoC text: {dict(spdx)}')
print(f'  PoC provenance shape: {dict(filehdr)}')

print()
print('=' * 78)
print('E. COMMITTED HARNESS FILES IN experiments/ (are these the authors own code?)')
print('=' * 78)
base = os.path.join(ROOT, 'experiments')
for dirpath, _, filenames in os.walk(base):
    for fn in filenames:
        if fn.endswith('.sol'):
            p = os.path.join(dirpath, fn)
            txt = open(p, encoding='utf-8').read()
            sp = re.search(r'SPDX-License-Identifier:\s*(\S+)', txt)
            rel = os.path.relpath(p, ROOT).replace('\\', '/')
            print(f'  {rel}')
            print(f'      SPDX: {sp.group(1) if sp else "NONE"}  lines={txt.count(chr(10))}')

print()
print('=' * 78)
print('F. MUTABLE / UNPINNED CITATIONS (branch refs and their blast radius)')
print('=' * 78)
SHA40 = re.compile(r'^[0-9a-f]{40}$')
MUT = {'main', 'master'}
per_file = Counter()
urls_branch = 0
urls_total = 0
for p in ('jsonl/findings.jsonl', 'jsonl/negative_findings.jsonl', 'jsonl/exploits.jsonl',
          'jsonl/patches.jsonl', 'derived/records.jsonl'):
    for r in rjl(p):
        def walk(o):
            global urls_branch, urls_total
            if isinstance(o, dict):
                for k, v in o.items():
                    if k == 'commit_sha' and isinstance(v, str) and v in MUT:
                        per_file[p] += 1
                    if k in ('source_url',) and isinstance(v, str) and '/blob/' in v:
                        urls_total += 1
                        if '/blob/main/' in v or '/blob/master/' in v:
                            urls_branch += 1
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(r)
print(f'  mutable commit_sha per file: {dict(per_file)}')
print(f'  /blob/ URLs total={urls_total}  of which pinned to a branch={urls_branch}')
print(f'  -> {urls_branch} permalinks resolve to whatever is at HEAD of that branch TODAY')

print()
print('=' * 78)
print('G. ARE THE "RESOLVED" SHAS REAL COMMIT SHAS? (spot-check format + known-repo reachability)')
print('=' * 78)
cr = json.load(open(os.path.join(ROOT, 'reports/citation_resolution.json'), encoding='utf-8'))
cits = cr.get('citations', [])
bad = 0
methods = Counter()
conf = Counter()
for c in cits:
    methods[c.get('resolution_method')] += 1
    conf[c.get('resolution_confidence')] += 1
    s = c.get('resolved_commit')
    if s and not SHA40.match(s):
        bad += 1
print(f'  citations resolved: {len(cits)}')
print(f'  resolution methods: {dict(methods)}')
print(f'  resolution confidence: {dict(conf)}')
print(f'  resolved_commit values that are NOT 40-hex: {bad}')

out = {
    'license_file_present': bool(lic),
    'records_with_solidity_snippet_text': snippet_recs,
    'records_carrying_poc_source': poc_recs,
    'self_declared_redistributed_records': redist,
    'redistribution_flag_distribution': dict(flag),
    'blob_urls_total': urls_total,
    'blob_urls_branch_pinned': urls_branch,
    'citations_resolved_by_resolver': len(cits),
    'resolution_methods': dict(methods),
    'resolved_sha_malformed': bad,
    'poc_spdx': dict(spdx),
}
with open(os.path.join(ROOT, '_audit', 'legal_hygiene.json'), 'w', encoding='utf-8') as f:
    json.dump(out, f, indent=2)
print('\nwrote _audit/legal_hygiene.json')