"""Post-apply verification, independent of the repo's scripts."""
import json, re, sys
from collections import Counter

SHA40 = re.compile(r'^[0-9a-f]{40}$')
MUT = {'main', 'master', 'develop', 'release-v5.0', 'release', 'HEAD', 'dev', 'latest'}
BLOB = re.compile(r'^https://github\.com/([^/]+/[^/]+)/blob/([^/]+)/')
KEYS = ('code_context', 'code_context_expanded', 'code_reference_only', 'vulnerable_code')

def scan(path):
    c = Counter()
    rows = 0
    for line in open(path, encoding='utf-8'):
        if not line.strip():
            continue
        rows += 1
        r = json.loads(line)
        for k in KEYS:
            for e in (r.get(k) or []):
                if not isinstance(e, dict):
                    continue
                sha = e.get('commit_sha')
                if not sha:
                    c['no_commit_sha'] += 1
                elif SHA40.match(sha):
                    c['sha_40hex'] += 1
                elif sha in MUT:
                    c['MUTABLE_' + sha] += 1
                else:
                    c['other_nonhex'] += 1
                m = BLOB.match(e.get('source_url') or '')
                if m:
                    c['url_40hex' if SHA40.match(m.group(2)) else 'URL_MUTABLE_' + m.group(2)] += 1
    return rows, c

print('=' * 70)
print('derived/records.jsonl  (the layer resolve_citations.py now writes)')
print('=' * 70)
rows, c = scan('derived/records.jsonl')
print('  rows:', rows)
for k, v in sorted(c.items()):
    print(f'    {v:6d}  {k}')

print()
print('=' * 70)
print('jsonl/  (read-only original evidence layer - MUST be unchanged)')
print('=' * 70)
tot = Counter()
for f in ('findings', 'negative_findings', 'exploits', 'patches'):
    _, c2 = scan(f'jsonl/{f}.jsonl')
    for k, v in c2.items():
        tot[k] += v
for k, v in sorted(tot.items()):
    print(f'    {v:6d}  {k}')

print()
d_mut = sum(v for k, v in c.items() if k.startswith(('MUTABLE', 'URL_MUTABLE')))
j_mut = sum(v for k, v in tot.items() if k.startswith(('MUTABLE', 'URL_MUTABLE')))
print(f'RESULT  mutable in derived/ = {d_mut}   mutable in jsonl/ = {j_mut}')
print('PASS' if d_mut == 0 else 'FAIL', '- derived layer is fully pinned'
      if d_mut == 0 else '- derived layer still holds mutable refs')

# audit trail present?
missing_audit = 0
pinned = 0
for line in open('derived/records.jsonl', encoding='utf-8'):
    if not line.strip():
        continue
    r = json.loads(line)
    for k in KEYS:
        for e in (r.get(k) or []):
            if isinstance(e, dict) and e.get('original_reference'):
                pinned += 1
                for need in ('source_url_original', 'resolution_method',
                             'resolution_confidence', 'commit_pinned_by'):
                    if not e.get(need):
                        missing_audit += 1
print(f'\naudit trail: {pinned} newly pinned citations, {missing_audit} missing provenance fields')