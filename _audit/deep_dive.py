"""Deep-dive: mutable citations in the DERIVED layer, which validate.py never checks."""
import json, re, os
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHA40 = re.compile(r'^[0-9a-f]{40}$')
MUTABLE = {'main', 'master', 'dev', 'develop', 'HEAD', 'latest'}

def rjl(p):
    out = []
    with open(os.path.join(ROOT, p), encoding='utf-8') as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out

def path_of(o, want, cur=''):
    """Yield json-path for every occurrence of key `want` whose value is in MUTABLE."""
    if isinstance(o, dict):
        for k, v in o.items():
            np = f'{cur}.{k}'
            if k == want and isinstance(v, str) and v in MUTABLE:
                yield np, v
            yield from path_of(v, want, np)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from path_of(v, want, f'{cur}[{i}]')

recs = rjl('derived/records.jsonl')
print('=' * 78)
print('MUTABLE commit_sha OCCURRENCES IN derived/records.jsonl  (722 records)')
print('=' * 78)
paths = Counter()
byfield = Counter()
occ_total = 0
recs_affected = set()
for r in recs:
    for p, v in path_of(r, 'commit_sha'):
        occ_total += 1
        recs_affected.add(r.get('id'))
        # normalise array indices
        norm = re.sub(r'\[\d+\]', '[]', p)
        norm = re.sub(r'^derived/records\.jsonl', '', norm)
        paths[norm] += 1
        # the field name immediately before commit_sha
        m = re.findall(r'\.([a-z_]+)(?:\[\d+\])?\.commit_sha$', p)
        byfield[m[0] if m else '?'] += 1
print(f'  total mutable commit_sha occurrences : {occ_total}')
print(f'  records affected                     : {len(recs_affected)} of {len(recs)}')
print()
print('  by parent field:')
for k, c in byfield.most_common(12):
    print(f'    {k:44s} {c:5d}')
print()
print('  by json-path shape (top 18):')
for k, c in paths.most_common(18):
    print(f'    {c:5d}  {k}')

print()
print('=' * 78)
print('SAME MAPPING IN THE READ-ONLY jsonl/ LAYER (validate.py DOES check this)')
print('=' * 78)
jl = Counter(); jt = 0
for f in ('findings.jsonl', 'negative_findings.jsonl', 'exploits.jsonl', 'patches.jsonl'):
    for r in rjl('jsonl/' + f):
        for p, v in path_of(r, 'commit_sha'):
            jt += 1
            m = re.findall(r'\.([a-z_]+)(?:\[\d+\])?\.commit_sha$', p)
            jl[m[0] if m else '?'] += 1
print(f'  total mutable commit_sha occurrences : {jt}')
for k, c in jl.most_common(12):
    print(f'    {k:44s} {c:5d}')

print()
print('=' * 78)
print('REPORT SELF-CLAIM vs DATA')
print('=' * 78)
cr = json.load(open(os.path.join(ROOT, 'reports/citation_resolution.json'), encoding='utf-8'))
print('  citation_resolution.json:')
print('    remaining_mutable_occurrences =', cr.get('remaining_mutable_occurrences'))
print('    occurrences_by_status        =', cr.get('occurrences_by_status'))
print('    top-level keys               =', [k for k in cr][:20])
res = cr.get('resolved') or cr.get('citations') or cr.get('details') or []
print('    len(resolved/detail array)   =', len(res) if isinstance(res, (list, dict)) else 'n/a')
if isinstance(res, list) and res:
    print('    sample entry:', json.dumps(res[0], indent=2)[:600])

print()
print('=' * 78)
print('EXPERIMENT ARTEFACTS: do the 9 experiments really discriminate?')
print('=' * 78)
ve = json.load(open(os.path.join(ROOT, 'reports/verified_experiments.json'), encoding='utf-8'))
for e in ve['experiments']:
    print('-' * 70)
    print(f"  {e['finding_id']}  verdict={e.get('verdict')}  class={e.get('classification')}")
    for side in ('revisions',):
        rv = e.get(side)
        if isinstance(rv, dict):
            for k, v in rv.items():
                print(f'    rev {k}: {json.dumps(v)[:400]}')
    if e.get('inconclusive_reason'):
        print(f"    inconclusive_reason: {e['inconclusive_reason']}")
    print(f"    notes: {(e.get('notes') or '')[:300]}")

print()
print('=' * 78)
print('RAW result.json PER EXPERIMENT (vulnerable + fixed)')
print('=' * 78)
base = os.path.join(ROOT, 'experiments')
for d in sorted(os.listdir(base)):
    p = os.path.join(base, d)
    if not os.path.isdir(p):
        continue
    for side in ('vulnerable', 'fixed'):
        rj = os.path.join(p, side, 'result.json')
        if not os.path.exists(rj):
            continue
        j = json.load(open(rj, encoding='utf-8'))
        keep = {k: v for k, v in j.items() if k in (
            'status', 'result', 'exit_code', 'passed', 'failed', 'assertion',
            'forge_status', 'reproduced', 'impact_demonstrated', 'run_failure_reason',
            'failure_reason', 'command', 'tests_summary', 'summary')}
        print(f'  {d}/{side}: {json.dumps(keep)[:340]}')