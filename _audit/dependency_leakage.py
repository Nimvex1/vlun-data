"""Cross-split THIRD-PARTY DEPENDENCY leakage + proof that check_leakage.py cannot see it.

Repo-level splitting (README: "v1 splits by repository, so one protocol's source
never appears twice") only isolates the audited repositories. Code4rena findings
routinely cite EXTERNAL contracts - OpenZeppelin, Uniswap, Aave, Synthetix,
LayerZero, seaport. If a train finding and a test finding cite the same external
file at the same commit, the model has that file verbatim in its training set even
though no audited repository is shared.
"""
import json, os, re
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REPO_SPLIT = {                      # from splits_v2/ as committed
    '2022-05-alchemix': 'train', '2024-04-noya': 'train',
    '2024-01-decent': 'validation', '2024-01-renft': 'validation',
    '2024-08-wildcat': 'test', '2024-12-bakerfi': 'test',
    '2025-06-panoptic': 'test', '2025-08-gte-perps': 'test',
}
SPLITS = ('train', 'validation', 'test')
CIT = ('code_context', 'code_context_expanded', 'code_reference_only')

recs = [json.loads(l) for l in open(os.path.join(ROOT, 'derived/records.jsonl'), encoding='utf-8') if l.strip()]

print('=' * 78)
print('A. CROSS-SPLIT THIRD-PARTY DEPENDENCY LEAKAGE')
print('=' * 78)
# key = (org/repo, path, commit) of a NON-audited citation
idx = defaultdict(lambda: defaultdict(set))       # target -> split -> record ids
repo_of_target = defaultdict(lambda: defaultdict(set))
for r in recs:
    repo = (r.get('source') or {}).get('repository')
    split = REPO_SPLIT.get(repo)
    if not split:
        continue
    rid = r.get('id')
    for field in CIT:
        for e in (r.get(field) or []):
            f = e.get('file') or ''
            if '/' not in f:
                continue
            org_repo = '/'.join(f.split('/')[:2])
            if repo and repo in org_repo:
                continue                        # audited repo: protected by repo split
            tgt = (org_repo, f, e.get('commit_sha') or '?')
            idx[tgt][split].add(rid)
            repo_of_target[org_repo][split].add(repo)

print('\nA1. exact (org/repo, path, commit_sha) shared across splits:')
hits = 0
for tgt, sp in sorted(idx.items(), key=lambda kv: -sum(len(v) for v in kv[1].values())):
    if len(sp) > 1:
        hits += 1
        org = repo_of_target[tgt[0]]
        print(f'  {tgt[0]}/{tgt[1]} @ {tgt[2][:12]}')
        for s, ids in sp.items():
            print(f'      {s:11s} via {sorted(org[s])}  records={sorted(ids)}')
print(f'  --> {hits} shared external code targets across splits')

print('\nA2. same external REPO cited from >1 split (weaker signal, repo-level):')
repo_cross = 0
for org, sp in sorted(repo_of_target.items(), key=lambda kv: -len(kv[1])):
    if len(sp) > 1:
        repo_cross += 1
        print(f'  {org:45s} {dict((s, sorted(set(v))) for s, v in sp.items())}')
print(f'  --> {repo_cross} external repos span multiple splits')

# ---------------------------------------------------------------- blindness
print()
print('=' * 78)
print('B. WHY scripts/check_leakage.py CANNOT SEE THIS')
print('=' * 78)
print('check_leakage.py reads splits/*.jsonl (default --input=splits) and audits those rows.')
print('splits_v2/*.jsonl is a THIN PROJECTION. Field survival:')
full_keys = set(recs[0].keys())
for s in SPLITS:
    rows = [json.loads(l) for l in open(os.path.join(ROOT, 'splits_v2', f'{s}.jsonl'), encoding='utf-8') if l.strip()]
    k = set(rows[0].keys())
    missing = sorted(full_keys - k)
    n_cit_full = sum(len(r.get(f) or []) for r in recs for f in CIT)
    n_cit_split = sum(len(r.get(f) or []) for r in rows for f in CIT)
    print(f'\n  {s}: {len(rows)} rows, {len(k)} of {len(full_keys)} top-level keys survive')
    print(f'    DROPPED: {missing}')
    print(f'    citation entries  derived(whole corpus)={n_cit_full}  this split={n_cit_split}')

# quantify: how many external citations survive into the split rows at all
print()
print('=' * 78)
print('C. EXTERNAL CITATIONS PRESENT IN derived/ BUT ABSENT FROM splits_v2/')
print('=' * 78)
by_field = Counter()
tot = Counter()
for r in recs:
    repo = (r.get('source') or {}).get('repository')
    for field in CIT:
        for e in (r.get(field) or []):
            f = e.get('file') or ''
            if '/' not in f:
                continue
            org_repo = '/'.join(f.split('/')[:2])
            if repo and repo not in org_repo:
                by_field[field] += 1
                tot[repo] += 1
print(f'  external citations by field: {dict(by_field)}  total={sum(by_field.values())}')
print(f'  by audited repo: {dict(tot)}')
# what do the split rows actually contain?
split_ext = 0
for s in SPLITS:
    rows = [json.loads(l) for l in open(os.path.join(ROOT, 'splits_v2', f'{s}.jsonl'), encoding='utf-8') if l.strip()]
    for r in rows:
        repo = (r.get('source') or {}).get('repository')
        for e in (r.get('code_context') or []):
            f = e.get('file') or ''
            if '/' in f and repo and repo not in '/'.join(f.split('/')[:2]):
                split_ext += 1
print(f'  external citations surviving INTO splits_v2/ code_context: {split_ext}')
print(f'  -> the author\'s leakage detectors operate on a projection that dropped '
      f'{sum(by_field.values()) - split_ext} of {sum(by_field.values())} external citations')

out = {
    'shared_external_targets_cross_split': hits,
    'external_repos_spanning_splits': repo_cross,
    'external_citations_by_field': dict(by_field),
    'external_citations_surviving_into_splits_v2': split_ext,
    'note': 'check_leakage.py audits splits/*.jsonl, a thin projection without '
            'code_reference_only / code_context_expanded, so third-party dependency '
            'leakage is structurally invisible to it.',
}
with open(os.path.join(ROOT, '_audit', 'dependency_leakage.json'), 'w', encoding='utf-8') as f:
    json.dump(out, f, indent=2)
print('\nwrote _audit/dependency_leakage.json')