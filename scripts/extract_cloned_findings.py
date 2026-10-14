import re, json, hashlib, datetime
from pathlib import Path
from pypdf import PdfReader

ROOT=Path(r"C:\Users\jeet\Downloads\vlun-data-main\vlun-data-main")
OUT_DIR=ROOT/"work"/"cloned_conversion"/"v4"
OUT_DIR.mkdir(parents=True, exist_ok=True)
import os as _os
out = OUT_DIR/"extracted_findings.jsonl"
_MODE = "a" if _os.environ.get("APPEND") else "w"
fh = open(out, _MODE, encoding="utf-8")

SOURCES = [
    ("halborn_public_reports", "Halborn Security Public Reports", ROOT/"work/new_sources/halborn_reports", "https://github.com/HalbornSecurity/PublicReports"),
    ("oak_security_audit_reports", "Oak Security audit reports", ROOT/"work/new_sources/oak_audit_reports", "https://github.com/oak-security/audit-reports"),
    ("coinfabrik_audit_reports", "CoinFabrik audit reports", ROOT/"work/new_sources/coinfabrik_reports", "https://github.com/CoinFabrik/coinfabrik-audit-reports"),
]

def git_head(repo):
    import subprocess
    try:
        return subprocess.check_output(["git","-C",str(repo),"rev-parse","HEAD"],text=True,stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "unknown"

def sha256_file(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(65536),b""):
            h.update(c)
    return h.hexdigest()

def pages_of(p):
    r=PdfReader(str(p))
    return [(i+1, (pg.extract_text(extraction_mode='layout') or '')) for i,pg in enumerate(r.pages)]

hal_pat=re.compile(r'(?m)^\s*\d+\.\d+\s*\(([A-Z0-9\-]+)\)\s*(.+?)\s*-\s*(CRITICAL|HIGH|MEDIUM|LOW|MAJOR|MINOR|INFORMATIONAL|INFO)\b',re.I)
oak_pat=re.compile(r'(?m)^\s*(\d+)\.\s+(.+?)\s+Severity:\s*(Critical|Major|Minor|Informational|High|Medium|Low)\b',re.I)
cf_pat=re.compile(r'(?m)^\s*([A-Z]{1,3}-\d+)\s+(.+?)\s+(Critical|High|Medium|Low|Minor|Major|Informational)\b',re.I)

def clean(s):
    return re.sub(r'\s+',' ',s).strip()

def classify_language_ecosystem(text, top, path):
    low = (text+" "+str(path)).lower()
    lang="unknown"; eco="unknown"
    if "solidity" in low or Path(path).parts and "solidity" in str(path).lower():
        lang="solidity"; eco="evm"
    if "cosmos" in low or "golang" in low :
        pass
    if "algorand" in low or "pyteal" in low:
        lang="teal"; eco="algorand"
    if "cosmos" in low or "go " in low or "golang" in low:
        lang="go"; eco="cosmos"
    if "rust" in low or ".rs" in low:
        lang="rust"
    if "move" in low:
        lang="move"
    if "cairo" in low:
        lang="cairo"
    # path-driven
    if "Solidity Smart Contract Audits" in str(path):
        lang="solidity"; eco="evm"
    if "Algorand" in str(path):
        lang="teal"; eco="algorand"
    return lang,eco

def project_from_stem(stem):
    s=stem
    s=re.sub(r'^\d{4}-\d{2}(-\d{2})?\s*[-–]?\s*','',s)
    s=s.replace('_',' ')
    for w in ['Smart Contract Security Audit Report','Smart Contract Security Audit','Security Assessment Report','Security Audit Report','Audit Report','Executive Summary Report','Report','Final','v1.0','v1.1','v1 1']:
        s=s.replace(w,'')
    s=re.sub(r'\s+',' ',s).strip(' -_')
    return s or stem

def repo_commit_from_text(text):
    repo=None; commit=None
    mr=re.search(r'Repository\s*[:\-]?\s*(https?://[^\s)]+)',text,re.I)
    if mr: repo=mr.group(1).rstrip('.,;')
    if not repo:
        mr=re.search(r'(https?://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)',text,re.I)
        if mr: repo=mr.group(1)
    mc=re.search(r'Commit\s*[:\-]?\s*([0-9a-f]{7,40})\b',text,re.I)
    if mc: commit=mc.group(1)
    if not commit:
        mc=re.search(r'based on (?:the )?commit\s+([0-9a-f]{7,40})',text,re.I)
        if mc: commit=mc.group(1)
    if not commit:
        mc=re.search(r'commit\s+([0-9a-f]{7,40})',text,re.I)
        if mc: commit=mc.group(1)
    return repo,commit

def code_excerpt(body):
    lines=body.splitlines()
    code_lines=[ln for ln in lines if (ln.strip().startswith(' ') and any(c in ln for c in (';','{','}','=','('))) or 'function ' in ln]
    chunk='\n'.join(code_lines).strip()
    if len(chunk)<20:
        chunk=None
    elif len(chunk)>1200:
        chunk=chunk[:1200]
    return chunk

def affected_location(body):
    pats=re.findall(r'[A-Za-z0-9_./-]+\.(?:sol|go|rs|py|ts|js|move|cairo)(?::\d+(?:-\d+)?)?',body)
    # unique preserve
    seen=set(); out=[]
    for x in pats:
        if x not in seen:
            seen.add(x); out.append(x)
    return out[:10]

def affected_function(body):
    m=re.search(r'function\s+([A-Za-z0-9_]+)',body,re.I)
    if m: return m.group(1)
    m=re.search(r'Function\s+([A-Za-z0-9_]+)',body,re.I)
    if m: return m.group(1)
    return None

def split_fields(body, firm):
    body=body or ''
    impact=None; suggested_fix=None; status=None
    low=body
    # status
    m=re.search(r'Status:\s*(.+?)(?:\n|$)',body,re.I)
    if m: status=clean(m.group(1))
    # coinfabrik solution
    m=re.search(r'Solution\s*[:\-]?\s*(.+?)(?:\n|$)',body,re.I)
    if m and not status:
        status=clean(m.group(1))
    # remediation solved
    m=re.search(r'(?:Remediation Plan|Remediation):\s*(.+?)(?:\n\s*\n|$)',body,re.S|re.I)
    if m:
        if not suggested_fix:
            suggested_fix=clean(m.group(1))[:1000]
    # recommendation
    recs=re.split(r'Recommendation\s*[:\-]?\s*',body,flags=re.I,maxsplit=1)
    if len(recs)==2:
        tail=recs[1]
        # cut at Status/Solution
        tail=re.split(r'\n\s*(?:Status|Solution):',tail,flags=re.I,maxsplit=1)[0]
        suggested_fix=(suggested_fix or clean(tail)[:1500]) if clean(tail) else suggested_fix
    # impact/preconditions: text before Recommendation
    pre = re.split(r'Recommendation\s*[:\-]?',body,flags=re.I,maxsplit=1)[0]
    pre=clean(pre)
    if pre:
        impact=pre[:2000]
    return impact, suggested_fix, status

all_rows=[]
import os
_SOURCE_FILTER = os.environ.get('SOURCE_FILTER')
for source_id, source_name, repo_dir, source_url in SOURCES:
    if _SOURCE_FILTER and _SOURCE_FILTER not in source_id:
        continue
    head=git_head(repo_dir)
    firm = {'halborn_public_reports':'halborn','oak_security_audit_reports':'oak','coinfabrik_audit_reports':'coinfabrik'}[source_id]
    pat = {'halborn':hal_pat,'oak':oak_pat,'coinfabrik':cf_pat}[firm]
    _files = sorted(repo_dir.rglob("*.pdf"))
    _off = int(__import__("os").environ.get("OFFSET", "0"))
    _lim = int(__import__("os").environ.get("LIMIT", "999999"))
    for pdf in _files[_off:_off+_lim]:
        rel=pdf.relative_to(repo_dir).as_posix()
        top=pdf.relative_to(repo_dir).parts[0] if pdf.relative_to(repo_dir).parts else ''
        pages=pages_of(pdf)
        full='\n'.join(f'\n=====PAGE {i}=====\n{t}' for i,t in pages)
        matches=list(pat.finditer(full))
        # if multiple regex occurrences (TOC + detail), keep those followed by Recommendation/Severity in next 2000 chars
        filtered=[]
        for m in matches:
            following=full[m.end():m.end()+3000]
            if ('Recommendation' in following or 'Severity:' in following or 'Description' in following or 'Status:' in following):
                filtered.append(m)
        if not filtered:
            filtered=matches
        # dedup by id and page
        seen_ids=set(); chosen=[]
        for m in filtered:
            fid=m.group(1)
            # page
            preceding=full[:m.start()].count('=====PAGE')
            page=pages[min(preceding,len(pages)-1)][0] if pages else 1
            key=(fid,page)
            if fid in seen_ids and page>1:
                # keep first detailed occurrence? skip if id seen on earlier page
                pass
            if fid in seen_ids:
                continue
            seen_ids.add(fid)
            chosen.append((m,page))
        # fallback: if chosen empty use filtered
        if not chosen and filtered:
            chosen=[(m,1) for m in filtered]
        text_full=full
        repo,commit=repo_commit_from_text(text_full)
        lang,eco=classify_language_ecosystem(text_full, top, rel)
        for m,page in chosen:
            fid=clean(m.group(1))
            title=clean(m.group(2))
            sev=clean(m.group(3))
            nxt_positions=[mm.start() for mm in pat.finditer(full) if mm.start()>m.start()]
            body_end=nxt_positions[0] if nxt_positions else len(full)
            body=full[m.end():body_end]
            # remove page markers maybe keep
            impact,suggested_fix,status = split_fields(body,firm)
            locs=affected_location(body)
            func=affected_function(body)
            excerpt=code_excerpt(body)
            # normalized severity
            sev_low=sev.lower()
            norm=sev_low
            if sev_low in ('major',): norm='high'
            if sev_low in ('minor',): norm='low'
            if sev_low in ('informational','info'): norm='info'
            rid=f"{source_id}:{hashlib.sha256((rel+fid+title).encode()).hexdigest()[:12]}"
            rec={
                "record_type":"finding_v4",
                "dataset_version":"4.0-staging",
                "candidate_id":rid,
                "finding_id_original":fid,
                "source_id":source_id,
                "source_name":source_name,
                "source_type":"professional_audit_firm",
                "source_url":source_url,
                "source_repository_commit":head,
                "report_path":rel,
                "report_file_name":pdf.name,
                "report_sha256":sha256_file(pdf),
                "top_level_category":top,
                "project":project_from_stem(pdf.stem),
                "title":title,
                "finding_title":title,
                "language":lang,
                "ecosystem":eco,
                "original_severity":sev,
                "severity_reported":sev,
                "severity_normalized":norm,
                "affected_repository":repo,
                "vulnerable_commit":commit,
                "vulnerable_commit_confidence":"observed" if commit else "unknown",
                "affected_location":locs,
                "affected_function":func,
                "affected_code_excerpt":excerpt,
                "impact":impact,
                "preconditions":None,
                "suggested_fix":suggested_fix,
                "externally_attributed_status":status,
                "poc_test_location":None,
                "execution_command":None,
                "verification_level":"L0",
                "verification_status":"UNVERIFIED",
                "admitted":False,
                "decision":"CANDIDATE",
                "duplicate_of":None,
                "quarantine_reason":None,
                "source_pointer":f"{source_url}/blob/{head}/{rel}#page={page}",
                "source_page":page,
                "license":"unknown",
                "license_status":"unknown",
                "raw_body_excerpt":clean(body)[:1500] if body else None,
                "extracted_at":datetime.datetime.utcnow().isoformat()+"Z",
            }
            all_rows.append(rec)
            fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
            fh.flush()

# write
if False:
    pass  # final write disabled (incremental writes)
    for r in all_rows:
        f.write(json.dumps(r,sort_keys=True,ensure_ascii=False)+"\n")
print("extracted",len(all_rows))
from collections import Counter
print(Counter(r['source_id'] for r in all_rows))
print("with commit",sum(1 for r in all_rows if r['vulnerable_commit']))
print("with repo",sum(1 for r in all_rows if r['affected_repository']))
print("with loc",sum(1 for r in all_rows if r['affected_location']))







