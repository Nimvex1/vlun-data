"""INDEPENDENT leakage detector (audit artifact, not part of the pipeline).

The author's scripts/check_leakage.py runs ten detectors. All ten are
TEXT-IDENTITY tests: exact ids/urls/shas, identical or normalised snippets,
function signatures, file::function, token Jaccard, 4-shingle cosine,
identical patch diff, same fixing commit, normalised PoC body, root-cause
bag-of-words, attack-sequence signature.

Structural blind spot: none of them compare WHAT THE FINDING IS ABOUT. Two
records in different repositories that describe the same vulnerability class,
exploit the same contract name, cite the same third-party dependency, or were
written by the same submitter share no tokens, no shingles and no diffs - so
every author detector returns "clean" while a model trained on train has
already seen the test item's concept, dependency surface and author style.

This script adds five detectors the author does not have. It reads the
committed splits_v2/ and reports cross-split contamination.
"""
import json, os, re, sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLITS = ('train', 'validation', 'test')
MULTISET = 0.25          # taxonomy-class coverage above this = "same concept taught"
DEP_OVERLAP = 0.30       # third-party dependency file overlap
AUDIT = sys.argv[1] if len(sys.argv) > 1 else 'splits_v2'

def load(split):
    p = os.path.join(ROOT, AUDIT, f'{split}.jsonl')
    out = []
    with open(p, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out

def rid(r):
    return r.get('id') or (r.get('finding') or {}).get('id') or (r.get('provenance') or {}).get('record_id') or '?'

def repo(r):
    s = r.get('source') or {}
    return s.get('repository') or (r.get('provenance') or {}).get('repository') or '?'

# ---------------------------------------------------------------- taxonomy
# Splits are a thin projection that DROPS taxonomy. Rebuild it from the
# record's own class strings, which are present in the split rows.
def class_strings(r):
    f = r.get('finding') or {}
    out = set()
    for k in ('vulnerability_classes', 'c4_original', 'vulnerability_class'):
        v = f.get(k) or (r.get('taxonomy') or {}).get(k)
        if isinstance(v, str):
            out.add(v.strip().lower())
        elif isinstance(v, list):
            out.update(x.strip().lower() for x in v if isinstance(x, str))
    t = r.get('taxonomy') or {}
    for k in ('class', 'category', 'family', 'subtype'):
        if t.get(k):
            out.add(str(t[k]).strip().lower())
    return {x for x in out if x}

def detector_taxonomy(rows_by_split):
    idx = defaultdict(set)
    for s, rows in rows_by_split.items():
        for r in rows:
            for c in class_strings(r):
                idx[c].add(s)
    cross = {c: sorted(v) for c, v in idx.items() if len(v) > 1}
    # multiset overlap: train/test vocabulary Jaccard
    def vocab(s):
        v = set()
        for r in rows_by_split[s]:
            v |= class_strings(r)
        return v
    tr, te, va = vocab('train'), vocab('test'), vocab('validation')
    jac = lambda a, b: len(a & b) / len(a | b) if (a | b) else 0.0
    return {
        'classes_in_multiple_splits': len(cross),
        'train_test_class_jaccard': round(jac(tr, te), 3),
        'train_val_class_jaccard': round(jac(tr, va), 3),
        'train_only_classes': sorted(tr - te - va),
        'test_classes_never_in_train': sorted(te - tr),
        'top_shared_classes': sorted(
            ((c, len(idx[c])) for c in (tr & te)),
            key=lambda x: -x[1])[:15],
    }

# ------------------------------------------------- third-party dependency code
# Code4rena audits cite external repos (OpenZeppelin, Uniswap, Synthetix,
# Chainlink). If train and test cite the SAME external file, the model's
# training set contains that file verbatim - repository-level split integrity
# does not protect it, because the shared code lives in neither audited repo.
def external_citations(rows_by_split):
    idx = defaultdict(set)
    total_per_split = Counter()
    audited = {repo(r) for rows in rows_by_split.values() for r in rows}
    for s, rows in rows_by_split.items():
        for r in rows:
            for e in (r.get('code_context') or []):
                f = e.get('file') or ''
                if '/' not in f:
                    continue
                org_repo = '/'.join(f.split('/')[:2])
                total_per_split[s] += 1
                if repo(r) in org_repo:
                    continue          # same audited repository: covered by repo split
                idx[f'{org_repo}/{e.get("commit_sha") or "?"}'].add(s)
    cross = {k: sorted(v) for k, v in idx.items() if len(v) > 1}
    return {
        'citation_entries_per_split': dict(total_per_split),
        'external_targets': len(idx),
        'external_targets_in_multiple_splits': len(cross),
        'examples': dict(list(sorted(cross.items()))[:12]),
    }

# ---------------------------------------------------------------- author style
def detector_author(rows_by_split):
    idx = defaultdict(set)
    for s, rows in rows_by_split.items():
        for r in rows:
            a = (r.get('finding') or {}).get('author')
            if a:
                idx[str(a).strip().lower()].add(s)
    cross = {a: sorted(v) for a, v in idx.items() if len(v) > 1}
    return {
        'distinct_authors': len(idx),
        'authors_in_multiple_splits': len(cross),
        'examples': dict(sorted(cross.items())[:15]),
    }

# --------------------------------------------------- contract-name collision
# Same contract NAME in train and test = same architectural pattern / role,
# even when the code and prose share no tokens.
def detector_contract_names(rows_by_split):
    idx = defaultdict(set)
    for s, rows in rows_by_split.items():
        for r in rows:
            names = set()
            for e in (r.get('code_context') or []):
                for k in ('contract',):
                    if e.get(k):
                        names.add(str(e[k]).strip())
            for a in ((r.get('finding') or {}).get('affected_contracts') or []):
                names.add(str(a).strip())
            for n in names:
                if n:
                    idx[n].add(s)
    cross = {n: sorted(v) for n, v in idx.items() if len(v) > 1}
    return {
        'distinct_contract_names': len(idx),
        'contract_names_in_multiple_splits': len(cross),
        'train_test_shared': sorted(set(cross) & set(
            [n for n, v in idx.items() if 'train' in v and 'test' in v])),
        'examples': dict(sorted(cross.items())[:15]),
    }

# ------------------------------------------- affected-function-name collision
def detector_function_names(rows_by_split):
    idx = defaultdict(set)
    for s, rows in rows_by_split.items():
        for r in rows:
            for e in (r.get('code_context') or []):
                fn = e.get('function')
                if fn:
                    idx[str(fn).strip()].add(s)
    cross = {n: sorted(v) for n, v in idx.items() if len(v) > 1}
    tr_test = sorted(n for n, v in idx.items() if 'train' in v and 'test' in v)
    return {
        'distinct_function_names': len(idx),
        'function_names_in_multiple_splits': len(cross),
        'train_test_shared_count': len(tr_test),
        'train_test_shared_top': tr_test[:30],
    }

# ------------------------------------------------------------------ report
def main():
    rows_by_split = {s: load(s) for s in SPLITS}
    print('=' * 78)
    print(f'INDEPENDENT LEAKAGE AUDIT  (source: {AUDIT}/)')
    print('=' * 78)
    for s, rows in rows_by_split.items():
        print(f'  {s:11s} {len(rows):4d} records, repos={sorted({repo(r) for r in rows})}')
    q = os.path.join(ROOT, AUDIT, 'quarantine.jsonl')
    if os.path.exists(q):
        print(f'  quarantine  {sum(1 for _ in open(q, encoding="utf-8") if _.strip())} records')

    findings = {}
    for name, fn in (('1_taxonomy_class_overlap', detector_taxonomy),
                     ('2_third_party_dependency_overlap', external_citations),
                     ('3_submitter_author_overlap', detector_author),
                     ('4_contract_name_collision', detector_contract_names),
                     ('5_function_name_collision', detector_function_names)):
        r = fn(rows_by_split)
        findings[name] = r
        print()
        print('-' * 78)
        print(name)
        print('-' * 78)
        print(json.dumps(r, indent=2)[:2200])

    # save
    with open(os.path.join(ROOT, '_audit', 'independent_leakage.json'), 'w',
              encoding='utf-8') as f:
        json.dump({'audited_splits': AUDIT,
                   'detectors': findings,
                   'author_detectors_blind_spot':
                       'all ten author detectors are text-identity tests; none compare '
                       'vulnerability class, dependency target, submitter or contract role'},
                  f, indent=2)
    print()
    print('wrote _audit/independent_leakage.json')

if __name__ == '__main__':
    main()