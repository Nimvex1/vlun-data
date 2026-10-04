"""Phase 5: is the benchmark well-formed and does it discriminate?

The repo ships 4109 tasks across 10 families and NO scorer, no rubric, no
baseline. This script (a) checks answer-key integrity and label balance,
(b) runs trivial baselines, (c) looks for answer leakage in the prompt.
"""
import json, os, re
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
B = os.path.join(ROOT, 'benchmark')

def load(name):
    return [json.loads(l) for l in open(os.path.join(B, name), encoding='utf-8') if l.strip()]

FAMS = [f for f in sorted(os.listdir(B)) if f.endswith('.jsonl')]

print('=' * 78)
print('A. ANSWER-KEY INTEGRITY / LABEL BALANCE PER FAMILY')
print('=' * 78)
for f in FAMS:
    rs = load(f)
    scorable = [r for r in rs if r.get('answer_key_status') == 'labeled']
    print(f'\n--- {f}  ({len(rs)} tasks, {len(scorable)} scorable)')
    if not scorable:
        print('    NO COMPLETE ANSWER KEY')
        continue
    ak = Counter()
    for r in scorable:
        k = r.get('answer_key')
        if isinstance(k, (dict, list)):
            k = json.dumps(k, sort_keys=True)
        ak[str(k)[:70]] += 1
    if len(ak) == 1:
        print(f'    !! SINGLE-CLASS: all {len(scorable)} scorable tasks share one answer '
              f'-> {list(ak)[0][:100]}')
    for k, c in ak.most_common(8):
        print(f'      {c:5d}  {k}')

print()
print('=' * 78)
print('B. SPLIT DISTRIBUTION OF SCORABLE TASKS (can test actually be run?)')
print('=' * 78)
for f in FAMS:
    rs = load(f)
    c = Counter(r.get('split') for r in rs if r.get('answer_key_status') == 'labeled')
    print(f'  {f:38s} scorable by split: {dict(c)}')

print()
print('=' * 78)
print('C. TRIVIAL BASELINES on the scorable tasks')
print('=' * 78)

def majority_baseline(rs):
    """Always answer the most frequent gold answer. Perfect-knowledge-of-prior baseline."""
    sc = [r for r in rs if r.get('answer_key_status') == 'labeled']
    if not sc:
        return None
    keys = []
    for r in sc:
        k = r.get('answer_key')
        if isinstance(k, (dict, list)):
            k = json.dumps(k, sort_keys=True)
        keys.append(str(k))
    maj = Counter(keys).most_common(1)[0][0]
    prior = Counter(keys).most_common(1)[0][1] / len(keys)
    # accuracy of always-majority, honestly computed per split
    accs = {}
    for sp in ('train', 'validation', 'test'):
        sub = [(r, k) for r, k in zip(sc, keys) if r.get('split') == sp]
        if sub:
            accs[sp] = round(sum(1 for _, k in sub if k == maj) / len(sub), 4)
    return len(sc), round(prior, 4), accs, maj[:80]

for f in FAMS:
    rs = load(f)
    res = majority_baseline(rs)
    if res:
        n, prior, accs, maj = res
        print(f'\n  {f}')
        print(f'    scorable={n}  train-prior(majority share)={prior}  '
              f'always-majority acc by split={accs}')
        print(f'    majority answer: {maj}')

print()
print('=' * 78)
print('D. ANSWER LEAKAGE: does the prompt contain the answer key verbatim?')
print('=' * 78)
for f in FAMS:
    rs = [r for r in load(f) if r.get('answer_key_status') == 'labeled']
    if not rs:
        continue
    leaks = 0
    checked = 0
    for r in rs:
        k = r.get('answer_key')
        if isinstance(k, (dict, list)):
            k = json.dumps(k, sort_keys=True)
        k = str(k).strip()
        if len(k) < 12:
            continue
        inp = json.dumps(r.get('input'), ensure_ascii=False)
        checked += 1
        if k in inp:
            leaks += 1
    print(f'  {f:38s} answer-string present in input: {leaks}/{checked}')

print()
print('=' * 78)
print('E. INPUT SCHEMA SANITY (are tasks well-formed?)')
print('=' * 78)
for f in FAMS:
    rs = load(f)
    ik = Counter()
    empty = 0
    for r in rs:
        i = r.get('input')
        if isinstance(i, dict):
            ik.update(i.keys())
        else:
            ik['<not a dict>'] += 1
        if not i or (isinstance(i, (dict, str)) and not i):
            empty += 1
    print(f'\n  {f}: empty input={empty}/{len(rs)}')
    print(f'    input keys: {dict(ik)}')

print()
print('=' * 78)
print('F. SCORER / RUBRIC / BASELINE INVENTORY')
print('=' * 78)
hits = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    if any(x in dirpath for x in ('.git', 'work', 'node_modules')):
        continue
    for fn in filenames:
        low = fn.lower()
        if any(k in low for k in ('scor', 'grade', 'baseline', 'rubric', 'predict')):
            hits.append(os.path.relpath(os.path.join(dirpath, fn), ROOT).replace('\\', '/'))
print('  files that look like a scorer/baseline/rubric:', hits or 'NONE')
print('  README mentions a scoring command:',
      'yes' if 'scor' in open(os.path.join(ROOT, 'README.md'), encoding='utf-8').read().lower() else 'no')
for cand in ('SCORING.md', 'EVAL.md', 'BENCHMARK.md', 'USAGE.md', 'requirements.txt',
             'pyproject.toml', 'setup.py', 'environment.yml', 'CITATION.cff',
             'LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING'):
    print(f'  {cand:22s} {"present" if os.path.exists(os.path.join(ROOT, cand)) else "MISSING"}')