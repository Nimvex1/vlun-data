import json, hashlib, os, datetime
from pathlib import Path
from difflib import SequenceMatcher
ROOT=Path(r"C:\Users\jeet\Downloads\vlun-data-main\vlun-data-main")
OUT_JSONL4=ROOT/"jsonl_v4"
OUT_DER4=ROOT/"derived_v4"
OUT_V4=ROOT/"V4"
for d in (OUT_JSONL4,OUT_DER4,OUT_V4):
    d.mkdir(parents=True, exist_ok=True)

def load_jsonl(p):
    if not Path(p).exists(): return []
    out=[]
    for line in open(p,encoding='utf-8'):
        line=line.strip()
        if not line: continue
        try: out.append(json.loads(line))
        except: pass
    return out

# extracted findings
findings=[json.loads(l) for l in open(ROOT/"work/cloned_conversion/v4/extracted_findings.jsonl",encoding='utf-8') if l.strip()]
# dedup whitespace/title normalization
def norm(s):
    return ''.join(ch for ch in str(s or '').lower() if ch.isalnum())
def title_of(r): return r.get('title') or r.get('finding_title') or ''
def repo_of(r): return r.get('affected_repository') or r.get('repository') or ''
def commit_of(r): return r.get('vulnerable_commit') or ''
def func_of(r): return r.get('affected_function') or ''
def sim(a,b):
    a=' '.join(str(a or '').lower().split()); b=' '.join(str(b or '').lower().split())
    if not a or not b: return 0.0
    return SequenceMatcher(None,a,b).ratio()

# existing records
existing=[]
for p in [ROOT/"jsonl/findings.jsonl"]:
    for r in load_jsonl(p): existing.append(r)
for p in (ROOT/"jsonl_ml").glob("findings_*.jsonl"):
    for r in load_jsonl(p): existing.append(r)
for r in load_jsonl(ROOT/"jsonl_v3/findings.jsonl"): existing.append(r)
for r in load_jsonl(ROOT/"Vbeta/jsonl_vbeta/findings.jsonl"): existing.append(r)

# index existing
by_repo={}
by_commit={}
for r in existing:
    key_repo=(repo_of(r) or '').lower()
    key_commit=commit_of(r) or ''
    if key_repo and key_repo not in ('unknown','') :
        by_repo.setdefault(key_repo,[]).append(r)
    if key_commit and key_commit not in ('unknown',None,''):
        by_commit.setdefault(key_commit,[]).append(r)

# staged candidates
staged=[json.loads(l) for l in open(ROOT/"work/cloned_conversion/staged_report_candidates.jsonl",encoding='utf-8') if l.strip()]

# within-extracted dedup
seen_title_keys=set()
admitted=[]; quarantined=[]; duplicates=[]; candidate_ledger=[]
for f in findings:
    rid=f.get('candidate_id')
    # missing core
    if not f.get('title') or not f.get('original_severity'):
        rec=dict(f); rec['decision']='QUARANTINED'; rec['quarantine_reason']='missing_core_fields'
        quarantined.append(rec); candidate_ledger.append({'candidate_id':rid,'decision':'QUARANTINED','reason':'missing_core_fields','source_id':f['source_id']}); continue
    # dedup existing
    repo=(repo_of(f) or f.get('affected_repository') or '').lower()
    commit=f.get('vulnerable_commit')
    cands=set()
    for r in by_repo.get(repo,[]): cands.add(id(r))
    if commit and commit not in ('unknown',None):
        for r in by_commit.get(commit,[]): cands.add(id(r))
    # map back
    cand_list=[r for r in existing if id(r) in cands] if cands else []
    # exact title key within extracted
    key=(f['source_id'], norm(f.get('title')))
    within_dup = False  # disabled: shared titles across reports are not duplicates
    best_score=0.0; best_ref=None; best_ts=0.0
    for r in cand_list:
        s=0.0
        if (r.get('source_url') or r.get('source_location')) == f.get('source_url'):
            s+=1.0
        if repo and repo == (repo_of(r) or '').lower():
            s+=0.35
        if commit and commit not in ('unknown',None) and commit == (commit_of(r) or ''):
            s+=0.3
        if func_of(f) and func_of(f)==func_of(r):
            s+=0.15
        ts=sim(title_of(r), f.get('title'))
        if ts>=0.92: s+=0.4
        elif ts>=0.8: s+=0.2
        codehash_e=hashlib.sha256((str(title_of(r))+str(repo_of(r))+str(commit_of(r))+str(func_of(r))).encode()).hexdigest()
        codehash_f=hashlib.sha256((str(f.get('title'))+str(f.get('affected_repository'))+str(commit)+str(f.get('affected_function'))).encode()).hexdigest()
        if codehash_e==codehash_f:
            s+=0.5
        if s>best_score:
            best_score=s; best_ref=r; best_ts=ts
    # store key
    seen_title_keys.add(key)
    # classify
    if within_dup:
        rec=dict(f); rec['decision']='DUPLICATE'; rec['duplicate_of']=rid+'-earlier'
        rec['quarantine_reason']=None
        duplicates.append(rec); candidate_ledger.append({'candidate_id':rid,'decision':'DUPLICATE','reason':'within_extracted','source_id':f['source_id']}); continue
    if best_score>=0.85:
        refid=best_ref.get('candidate_id') if isinstance(best_ref,dict) else None
        if not refid:
            refid=best_ref.get('source_location') if isinstance(best_ref,dict) else str(best_ref)
        rec=dict(f); rec['decision']='DUPLICATE'; rec['duplicate_of']=refid
        duplicates.append(rec); candidate_ledger.append({'candidate_id':rid,'decision':'DUPLICATE','reason':'existing_match','score':best_score,'source_id':f['source_id']}); continue
    if best_score>=0.55:
        rec=dict(f); rec['decision']='QUARANTINED'; rec['quarantine_reason']='conflicting_duplicate'
        quarantined.append(rec); candidate_ledger.append({'candidate_id':rid,'decision':'QUARANTINED','reason':'conflicting_duplicate','score':best_score,'source_id':f['source_id']}); continue
    rec=dict(f); rec['decision']='ADMITTED'; rec['admitted']=True
    admitted.append(rec); candidate_ledger.append({'candidate_id':rid,'decision':'ADMITTED','source_id':f['source_id']})

# write ledgers
def write_jsonl(path, rows):
    with open(path,'w',encoding='utf-8',newline='\n') as fh:
        for r in rows:
            fh.write(json.dumps(r,sort_keys=True,ensure_ascii=False)+'\n')

write_jsonl(OUT_JSONL4/"findings.jsonl", admitted)
# sources.jsonl
sources_rows=[]
for sid,sname,repo,source_url in [
    ("halborn_public_reports","Halborn Security Public Reports",ROOT/"work/new_sources/halborn_reports","https://github.com/HalbornSecurity/PublicReports"),
    ("oak_security_audit_reports","Oak Security audit reports",ROOT/"work/new_sources/oak_audit_reports","https://github.com/oak-security/audit-reports"),
    ("coinfabrik_audit_reports","CoinFabrik audit reports",ROOT/"work/new_sources/coinfabrik_reports","https://github.com/CoinFabrik/coinfabrik-audit-reports"),
]:
    import subprocess
    head=subprocess.check_output(["git","-C",str(repo),"rev-parse","HEAD"],text=True,stderr=subprocess.DEVNULL).strip()
    sources_rows.append({"source_id":sid,"source_name":sname,"source_url":source_url,"source_type":"professional_audit_firm","source_repository_commit":head,"license_status":"unknown","record_type":"source_v4","dataset_version":"4.0"})
write_jsonl(OUT_JSONL4/"sources.jsonl", sources_rows)

write_jsonl(OUT_DER4/"candidate_ledger.jsonl", candidate_ledger)
write_jsonl(OUT_DER4/"admitted_ledger.jsonl", admitted)
write_jsonl(OUT_DER4/"quarantined_ledger.jsonl", quarantined)
write_jsonl(OUT_DER4/"duplicate_ledger.jsonl", duplicates)

manifest={
    "dataset_version":"4.0",
    "layer":"V4",
    "generated_at":datetime.datetime.utcnow().isoformat()+"Z",
    "source_candidates_staged":len(staged),
    "extracted_findings":len(findings),
    "admitted":len(admitted),
    "quarantined":len(quarantined),
    "duplicates":len(duplicates),
    "candidate_ledger":len(candidate_ledger),
    "reports_by_source":{"halborn_public_reports":1785,"oak_security_audit_reports":3259,"coinfabrik_audit_reports":226},
    "verification_levels":{"L0":len(findings)},
    "languages":{},
    "missing_provenance":sum(1 for f in findings if not f.get('affected_repository') or not f.get('vulnerable_commit')),
    "licensing_risks":["halborn_public_reports: no LICENSE file found","coinfabrik_audit_reports: no LICENSE file found","oak_security_audit_reports: CC BY-ND 4.0"],
}
from collections import Counter
manifest["languages"]=dict(Counter(f.get('language') for f in findings))
manifest["vulnerability_classes"]=dict(Counter(f.get('normalized_vulnerability_class','unknown') for f in findings))
import json as _j
(OUT_DER4/"manifest.json").write_text(_j.dumps(manifest,sort_keys=True,indent=2),encoding='utf-8')
# V4 top-level manifest copy
(OUT_V4/"manifest.json").write_text(_j.dumps(manifest,sort_keys=True,indent=2),encoding='utf-8')
(OUT_V4/"sources.json").write_text(_j.dumps(sources_rows,sort_keys=True,indent=2),encoding='utf-8')
print("counts",len(findings),len(admitted),len(quarantined),len(duplicates))
