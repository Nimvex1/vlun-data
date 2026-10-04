"""INDEPENDENT recomputation of README claims. Does NOT import repo scripts."""
import json, re, os, sys, hashlib
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHA40 = re.compile(r'^[0-9a-f]{40}$')
MUTABLE = {'main', 'master', 'dev', 'develop', 'HEAD', 'latest'}

def rj(p):
    with open(os.path.join(ROOT, p), encoding='utf-8') as f:
        return json.load(f)

def rjl(p):
    out = []
    with open(os.path.join(ROOT, p), encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

def sha_of(p):
    h = hashlib.sha256()
    with open(os.path.join(ROOT, p), 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()

R = []
def rec(claim, computed, expected, ok=None):
    if ok is None:
        ok = (computed == expected)
    R.append((claim, str(expected), str(computed), 'CONFIRMED' if ok else 'MISMATCH'))
    return ok

# ---------------------------------------------------------------- counts
print('=' * 78)
print('A. RECORD COUNTS  (README "Layout" block)')
print('=' * 78)
expected_counts = {
    'jsonl/findings.jsonl': 264, 'jsonl/negative_findings.jsonl': 458,
    'jsonl/exploits.jsonl': 155, 'jsonl/patches.jsonl': 38,
    'jsonl/protocol.jsonl': 8, 'jsonl/metadata.jsonl': 11,
    'jsonl/errors.jsonl': 19, 'derived/records.jsonl': 722,
    'derived/hard_negatives.jsonl': 458, 'derived/counterexamples.jsonl': 43,
}
for p, exp in expected_counts.items():
    n = sum(1 for _ in open(os.path.join(ROOT, p), encoding='utf-8') if _.strip())
    rec(f'line count {p}', n, exp)

# ---------------------------------------------------------------- provenance
print()
print('=' * 78)
print('B. CITATION IMMUTABILITY  (README: "Mutable branch citations 453 -> 0")')
print('=' * 78)

def all_commit_shas(obj):
    """Yield (path_to_field, sha_value) for every commit_sha-ish field."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ('commit_sha', 'sha', 'blob_sha', 'resolved_commit') and isinstance(v, str):
                yield k, v
            else:
                yield from all_commit_shas(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from all_commit_shas(v)

mutable_by_file = {}
total_mutable = 0
nonhex = {}
for p in ['jsonl/findings.jsonl', 'jsonl/negative_findings.jsonl', 'jsonl/exploits.jsonl',
          'jsonl/patches.jsonl', 'jsonl/protocol.jsonl', 'jsonl/metadata.jsonl',
          'jsonl/errors.jsonl']:
    m = 0; nh = 0
    for row in rjl(p):
        for k, v in all_commit_shas(row):
            if v in MUTABLE:
                m += 1
            elif not SHA40.match(v):
                nh += 1
    mutable_by_file[p] = m
    nonhex[p] = nh
    total_mutable += m
    print(f'  {p:42s} mutable={m:5d}  non-40hex={nh}')
print(f'  {"TOTAL jsonl/":42s} mutable={total_mutable:5d}')
rec('mutable branch citations in read-only jsonl/ layer', total_mutable, 453)

# derived layer
dm = 0; dn = 0
for row in rjl('derived/records.jsonl'):
    for k, v in all_commit_shas(row):
        if v in MUTABLE:
            dm += 1
        elif not SHA40.match(v):
            dn += 1
print(f'  {"derived/records.jsonl":42s} mutable={dm:5d}  non-40hex={dn}')
rec('mutable branch citations in derived/records.jsonl', dm, 0)

# all citation-shaped dicts (code_context / sources / patch refs)
def citation_entries(obj, keys=('commit_sha',)):
    found = []
    if isinstance(obj, dict):
        if any(k in obj for k in keys) and obj.get('file') or obj.get('path'):
            found.append(obj)
        for v in obj.values():
            found.extend(citation_entries(v, keys))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(citation_entries(v, keys))
    return found

allmut = 0
for p in expected_counts:
    if not p.startswith(('jsonl/', 'derived/')):
        continue
    for e in citation_entries(rjl(p)):
        s = e.get('commit_sha')
        if s in MUTABLE:
            allmut += 1
print(f'  file/paired citations with mutable commit_sha: {allmut}')

# citation_resolution.json self-report
cr = rj('reports/citation_resolution.json')
print(f'\n  citation_resolution.json self-report: '
      f'remaining_mutable_occurrences={cr.get("remaining_mutable_occurrences")} '
      f'by_status={cr.get("occurrences_by_status")}')

# ---------------------------------------------------------------- splits
print()
print('=' * 78)
print('C. SPLITS  (README: train 415 / validation 277 / test 253 / quarantined 2)')
print('=' * 78)
for split in ('train', 'validation', 'test'):
    rows = rjl(f'splits_v2/{split}.jsonl')
    rec(f'splits_v2/{split}.jsonl rows', len(rows),
        {'train': 415, 'validation': 277, 'test': 253}[split])
    repos = Counter((r.get('source') or r.get('provenance') or {}).get('repository')
                     for r in rows)
    print(f'    {split}: {len(rows)} rows, {len(repos)} repos -> {dict(sorted(repos.items()))}')
q = rjl('splits_v2/quarantine.jsonl')
rec('splits_v2/quarantine.jsonl rows', len(q), 2)
tot = sum(len(rjl(f'splits_v2/{s}.jsonl')) for s in ('train', 'validation', 'test'))
print(f'  415+277+253 = 945 ; actual total = {tot} ; +2 quarantined = {tot + len(q)}')

# ---------------------------------------------------------------- attacker model
print()
print('=' * 78)
print('D. ATTACKER MODEL / UNKNOWN COUNTS  (README limitation #3: 432/722 unknown)')
print('=' * 78)
recs = rjl('derived/records.jsonl')
print(f'  derived/records.jsonl rows = {len(recs)}')
key = None
sample = recs[0]
for k in sample:
    if 'attacker' in k.lower():
        key = k
        break
print(f'  attacker-ish top-level keys: {[k for k in sample if "attacker" in k.lower()]}')
am = None
for k in sample:
    if k == 'attacker_model' or 'attacker' in k.lower():
        am = k
        break
print(f'  using key: {am}')
vals = Counter()
unk = 0
for r in recs:
    v = r.get(am)
    if isinstance(v, dict):
        v = v.get('value')
    v = str(v)
    vals[v] += 1
    if v.lower() in ('unknown', 'none', 'null'):
        unk += 1
for k, c in vals.most_common():
    print(f'    {k:34s} {c}')
rec(f'records with unknown attacker identity', unk, 432)

# ---------------------------------------------------------------- PoC
print()
print('=' * 78)
print('E. PoC EXECUTION  (README: 155 total, 15 executed, 5 impact, 140 never run)')
print('=' * 78)
exp = rjl('jsonl/exploits.jsonl')
print(f'  exploits.jsonl = {len(exp)}')
repro = Counter()
lvl = Counter()
reproduced = 0
has_artifact = 0
for r in exp:
    repro[r.get('reproducible')] += 1
    lvl[r.get('quality_level') or r.get('poc_level')] += 1
    if r.get('reproduced') or r.get('impact_demonstrated'):
        reproduced += 1
print(f'  reproducible: {dict(repro)}')
print(f'  quality/poc level: {dict(sorted(lvl.items(), key=lambda x: str(x[0])))}')
rec('PoCs marked reproducible', repro.get(True, 0), 0)

vs = rj('reports/verification_stats.json')
print(f'\n  verification_stats.json: {json.dumps({k: v for k, v in vs.items() if not isinstance(v, (list, dict))}, indent=2)[:1200]}')

# ---------------------------------------------------------------- evidence
print()
print('=' * 78)
print('F. EVIDENCE SEMANTICS  (README: 7-value closed vocabulary)')
print('=' * 78)
VOCAB = {'observed_fact', 'reported_claim', 'derived_fact', 'experimentally_verified',
         'externally_attributed', 'unverified', 'unknown'}
seen = Counter()
def scan_evidence(o):
    if isinstance(o, dict):
        if 'evidence_type' in o and 'value' in o:
            seen[o['evidence_type']] += 1
        for v in o.values():
            scan_evidence(v)
    elif isinstance(o, list):
        for v in o:
            scan_evidence(v)
for p in ['derived/records.jsonl', 'derived/hard_negatives.jsonl', 'derived/counterexamples.jsonl']:
    for r in rjl(p):
        scan_evidence(r)
print(f'  observed evidence_type values: {dict(seen.most_common())}')
outside = set(seen) - VOCAB
print(f'  values OUTSIDE the README-documented 7: {outside or "none"}')

# ---------------------------------------------------------------- empty reasoning fields
print()
print('=' * 78)
print('G. EMPTY REASONING FIELDS in the source layer (not a README claim; my own check)')
print('=' * 78)
findings = rjl('jsonl/findings.jsonl')
for fld in ('summary', 'root_cause'):
    e = sum(1 for r in findings if not (r.get('finding', {}).get(fld) or '').strip())
    print(f'  findings.jsonl finding.{fld} empty: {e}/{len(findings)}')
for fld in ('broken_behavior',):
    e = sum(1 for r in findings if not (r.get('security_reasoning', {}).get(fld) or '').strip())
    print(f'  findings.jsonl security_reasoning.{fld} empty: {e}/{len(findings)}')
for fld in ('financial', 'protocol_state', 'availability', 'confidentiality'):
    e = sum(1 for r in findings if not (r.get('security_reasoning', {}).get('impact', {}).get(fld) or '').strip())
    print(f'  findings.jsonl security_reasoning.impact.{fld} empty: {e}/{len(findings)}')
e = sum(1 for r in findings if not (r.get('security_reasoning', {}).get('documented_intent') or '').strip())
e2 = sum(1 for r in findings if not (r.get('code_context') or [{}])[0].get('documented_intent', '').strip()
         if r.get('code_context'))
docintent = sum(1 for r in findings for c in (r.get('code_context') or []) if not (c.get('documented_intent') or '').strip())
totctx = sum(len(r.get('code_context') or []) for r in findings)
print(f'  findings.jsonl security_reasoning.documented_intent empty: {e}/{len(findings)}')
print(f'  code_context[*].documented_intent empty: {docintent}/{totctx}')
inv_empty = sum(1 for r in findings if not (r.get('security_reasoning', {}).get('invariants') or []))
print(f'  findings with invariants: [] -> {inv_empty}/{len(findings)} (README claims 35/264)')

# ---------------------------------------------------------------- license
print()
print('=' * 78)
print('H. LICENCE / REDISTRIBUTION')
print('=' * 78)
lic = Counter()
flag = Counter()
nolic = 0
for r in recs:
    l = r.get('license_classification')
    if isinstance(l, dict):
        l = l.get('value')
    lic[str(l)] += 1
    f = (r.get('redistribution') or {}).get('flag')
    if isinstance(f, dict):
        f = f.get('value')
    flag[str(f)] += 1
for k, c in lic.most_common():
    print(f'    license_classification={k:34s} {c}')
for k, c in flag.most_common():
    print(f'    redistribution.flag={k:34s} {c}')
nol = lic.get('none', 0) + lic.get('None', 0) + lic.get('unknown', 0)
print(f'  -> records with no/unknown licence: {nol} (README limitation #5 claims 424)')

# ---------------------------------------------------------------- experiments
print()
print('=' * 78)
print('I. EXPERIMENTS')
print('=' * 78)
exps = sorted(os.listdir(os.path.join(ROOT, 'experiments')))
exps = [e for e in exps if os.path.isdir(os.path.join(ROOT, 'experiments', e))]
print(f'  experiment dirs = {len(exps)}: {exps}')
ve = rj('reports/verified_experiments.json')
for k, v in ve.items():
    if not isinstance(v, (list, dict)):
        print(f'    verified_experiments.{k} = {v}')
print(f'    verified_experiments.records = {len(ve.get("records", []))}')
st = Counter()
for r in ve.get('records', []):
    st[(r.get('vulnerable_revision_result'), r.get('fixed_revision_result'))] += 1
print(f'    (vuln_result, fixed_result) pairs: {dict(st)}')
eff = [r for r in ve.get('records', []) if r.get('patch_effectiveness') == 'effective'
       or r.get('effective')]
print(f'    records labelled effective: {len(eff)}')

# ---------------------------------------------------------------- benchmarks
print()
print('=' * 78)
print('J. BENCHMARK')
print('=' * 78)
bm = rjl([f for f in os.listdir(os.path.join(ROOT, 'benchmark')) if f.endswith('.jsonl')])
for p in sorted(os.listdir(os.path.join(ROOT, 'benchmark'))):
    if p.endswith('.jsonl'):
        rows = rjl(f'benchmark/{p}')
        print(f'  {p:38s} {len(rows):5d} tasks')
bman = rj('benchmark/manifest.json')
print(f'  manifest families: {len(bman.get("families", bman)) if isinstance(bman.get("families", bman), (list, dict)) else "?"}')
print(f'  benchmark manifest keys: {list(bman)[:12]}')

print()
print('=' * 78)
print('SUMMARY TABLE')
print('=' * 78)
w = max(len(c) for c, *_ in R) + 2
bad = 0
for claim, exp, comp, verdict in R:
    if verdict == 'MISMATCH':
        bad += 1
    print(f'  {verdict:10s} {claim:<{w}s} readme={exp:<12s} computed={comp}')
print(f'\n  {len(R) - bad}/{len(R)} reproduced, {bad} mismatch')