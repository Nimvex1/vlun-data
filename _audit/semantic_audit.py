"""Phase 2: semantic correctness sampling, done independently.

30 records / 20 hard negatives / 10 counterexample sets, deterministic sample,
checked against the ORIGINAL jsonl/ evidence layer and the pinned citations
rather than against the derived layer's own claims.
"""
import json, os, re, hashlib
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def rjl(p): return [json.loads(l) for l in open(os.path.join(ROOT,p),encoding='utf-8') if l.strip()]
def H(s): return int(hashlib.sha256(str(s).encode()).hexdigest(),16)

recs = rjl('derived/records.jsonl')
orig_findings = {r['finding']['id']: r for r in rjl('jsonl/findings.jsonl')}
orig_negs     = {r['finding']['id']: r for r in rjl('jsonl/negative_findings.jsonl')}

print('='*78); print('A. 30-RECORD SAMPLE: does the derived record faithfully restate the original?'); print('='*78)
sample = sorted(recs, key=lambda r: H(r.get('id')))[:30]
sev_mismatch=[]; title_missing=[]; missing_in_orig=[]; att_issues=[]; ev_issues=[]
VOCAB={'observed_fact','reported_claim','derived_fact','experimentally_verified',
       'externally_attributed','unverified','unknown'}
for r in sample:
    rid=r.get('id')
    of=orig_findings.get(rid); on=orig_negs.get(rid)
    src = of or on
    if src is None:
        missing_in_orig.append(rid); continue
    # severity agreement with the ORIGINAL layer
    if (r.get('finding') or {}).get('severity') != (src.get('finding') or {}).get('severity'):
        sev_mismatch.append((rid,(r.get('finding') or {}).get('severity'),(src.get('finding') or {}).get('severity')))
    # title present
    if not (r.get('finding') or {}).get('title'):
        title_missing.append(rid)
    # attacker identity must be one of the 4 documented values
    ai=((r.get('attacker_model') or {}).get('attacker_identity') or {})
    v=ai.get('value')
    if v not in ('unprivileged','privileged','honest_but_misconfigured','malicious_dependency','unknown',None):
        att_issues.append((rid,v))
    # every evidence-wrapped value must carry an in-vocabulary type AND source_refs
    def scan(o,path=''):
        if isinstance(o,dict):
            if 'evidence_type' in o and 'value' in o:
                et=o.get('evidence_type')
                if et not in VOCAB:
                    ev_issues.append((rid,path,'bad evidence_type',et))
                if o.get('value') not in (None,'',[]) and not o.get('source_refs') and et in ('derived_fact','observed_fact','experimentally_verified'):
                    ev_issues.append((rid,path,'no source_refs for',et))
            for k2,v2 in o.items(): scan(v2,path+'.'+k2)
        elif isinstance(o,list):
            for i,v2 in enumerate(o): scan(v2,f'{path}[{i}]')
    scan(r)
print(f'  sampled 30: {len(sample)}')
print(f'  ids absent from the original jsonl layer      : {len(missing_in_orig)} {missing_in_orig[:5]}')
print(f'  severity disagreements with the original      : {len(sev_mismatch)} {sev_mismatch[:5]}')
print(f'  derived record missing title                  : {len(title_missing)} {title_missing[:5]}')
print(f'  attacker_identity outside documented vocabulary: {len(att_issues)} {att_issues[:5]}')
print(f'  evidence-semantics defects                     : {len(ev_issues)}')
for e in ev_issues[:12]: print('     ',e)

print()
print('='*78); print('B. attacker_model: is the classification consistent with its own stated rule?'); print('='*78)
cnt=Counter(); contradiction=[]
for r in recs:
    am=r.get('attacker_model') or {}
    ai=am.get('attacker_identity') or {}
    cnt[str(ai.get('value'))]+=1
    val=str(ai.get('value')); rule=str(ai.get('rule') or '')
    # a rule that says "role modifier present -> privileged" but a value of unprivileged
    if 'role modifier present -> privileged' in rule and val=='unprivileged':
        contradiction.append((r.get('id'),val,rule[:90]))
    if val=='unprivileged' and 'onlyMaintainer' in json.dumps(am) and 'only' in json.dumps(am).lower():
        pass
print('  attacker_identity distribution over all 722 records:')
for k,v in cnt.most_common(): print(f'    {k:32s} {v}')
print(f'  records whose stated rule contradicts their value: {len(contradiction)} {contradiction[:4]}')
unk=cnt.get('unknown',0)
print(f'  README limitation #3 claims 432/722 unknown -> ACTUAL {unk}/722')

print()
print('='*78); print('C. 20 HARD NEGATIVES: is the rejection reason code-grounded?'); print('='*78)
hn=rjl('derived/hard_negatives.jsonl')
print(f'  hard_negatives.jsonl rows: {len(hn)}')
print(f'  row keys: {list(hn[0])}')
s20=sorted(hn,key=lambda r:H(json.dumps(r,sort_keys=True)))[:20]
grounded=0;label_only=0;nulls=0;noev=0
for r in s20:
    bc=r.get('blocking_condition') or {}
    wc=r.get('why_exploit_fails') or {}
    has_code = bool(re.search(r'`\w+|\.sol|function |onlyOwner|nonReentrant', json.dumps(r)))
    v = bc.get('value') or wc.get('value')
    if bc.get('evidence_type')=='unknown' or (r.get('rejection_basis')=='label_only'): label_only+=1
    if not v: nulls+=1
    if has_code: grounded+=1
    else: noev+=1
print(f'  sample of 20: mentions concrete code identifiers: {grounded}/20')
print(f'                rejection_basis == label_only or blocking unknown: {label_only}/20')
print(f'                blocking_condition/why_exploit_fails value is null  : {nulls}/20')
basis=Counter(r.get('rejection_basis') for r in hn)
print(f'  rejection_basis over all {len(hn)}: {dict(basis)}')
print(f'  negative_class distribution: {dict(Counter(r.get("negative_class") for r in hn))}')

print()
print('='*78); print('D. 10 COUNTEREXAMPLE SETS: genuine counterexample or strawman?'); print('='*78)
ce=rjl('derived/counterexamples.jsonl')
print(f'  counterexamples.jsonl rows: {len(ce)}')
print(f'  keys: {list(ce[0])}')
s10=sorted(ce,key=lambda r:H(json.dumps(r,sort_keys=True)))[:10]
sib=0;stale=0
for r in s10:
    hyp=json.dumps(r.get('false_hypothesis') or r.get('hypothesis') or {})
    bl=json.dumps(r.get('blocking_behaviour') or r.get('blocked_behaviour') or '')
    same_file = (r.get('finding_file') or '') == (r.get('counterexample_file') or '')
    if 'sibling' in json.dumps(r).lower(): sib+=1
    print(f"   {r.get('id') or r.get('source_record',{}).get('id')}: sib={same_file} "
          f"hyp_len={len(hyp)} block_len={len(bl)}")
print(f'  rows mentioning a sibling/API pair: {sib}/10')

print()
print('='*78); print('E. does the derived layer cite code that the original layer never had?'); print('='*78)
extra=0;checked=0
for r in sample[:30]:
    rid=r.get('id'); src=orig_findings.get(rid) or orig_negs.get(rid)
    if not src: continue
    checked+=1
    ofiles={e.get('file') for e in (src.get('code_context') or [])}
    n=0
    for f in ('code_context_expanded','code_reference_only'):
        for e in (r.get(f) or []):
            if e.get('file') not in ofiles: n+=1
    if n: extra+=1
print(f'  records whose expanded context cites files absent from the original: {extra}/{checked}')
print('  (expected: expansion is legitimate, but those citations are new claims '
      'and are invisible to check_leakage.py, which runs on splits/*.jsonl)')