#!/usr/bin/env python3
"""Compare the deterministic engine against public sample answers."""
import csv, json, sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'code'))
from main import AuditEngine, read_csv

def main():
    reqs=read_csv(ROOT/'dataset'/'sample_deletion_requests.csv')
    gold={r['case_id']:r for r in read_csv(ROOT/'dataset'/'sample_output.csv')}
    engine=AuditEngine(); predictions={}
    for req in reqs:
        case,status,steps=engine.predict(req)
        predictions[case]={'deletion_status':status,'steps':steps}
    status_correct=sum(predictions[r['case_id']]['deletion_status']==gold[r['case_id']]['deletion_status'] for r in reqs)
    exact=sum(predictions[r['case_id']]['deletion_status']==gold[r['case_id']]['deletion_status'] and predictions[r['case_id']]['steps']==json.loads(gold[r['case_id']]['steps_json']) for r in reqs)
    field_names=['phase','system_id','resource_id','operation','state','evidence_id']
    pred_steps=[]; gold_steps=[]
    for r in reqs:
        pred_steps.extend([{k:s.get(k) for k in field_names} for s in predictions[r['case_id']]['steps']])
        gold_steps.extend([{k:s.get(k) for k in field_names} for s in json.loads(gold[r['case_id']]['steps_json'])])
    def sig(s): return tuple(s.get(k) for k in field_names)
    pc,gc=Counter(map(sig,pred_steps)),Counter(map(sig,gold_steps))
    matched=sum((pc & gc).values()); precision=matched/max(1,len(pred_steps)); recall=matched/max(1,len(gold_steps)); f1=2*precision*recall/max(1e-12,precision+recall)
    # Per-field accuracy is measured over paired exact sequence positions and is explicitly approximate
    # when the number of steps differs; exact sequence and exact array rates are separately reported.
    field_accuracy={k:0 for k in field_names}; denom=0; sequence_cases=0; missing=extra=0
    for r in reqs:
        p=predictions[r['case_id']]['steps']; g=json.loads(gold[r['case_id']]['steps_json'])
        if [sig(x) for x in p]==[sig(x) for x in g]: sequence_cases+=1
        missing += max(0,len(g)-len(p)); extra += max(0,len(p)-len(g))
        for i in range(min(len(p),len(g))):
            denom+=1
            for k in field_names: field_accuracy[k] += p[i].get(k)==g[i].get(k)
    print(f'Sample requests: {len(reqs)}')
    print(f'Status accuracy: {status_correct}/{len(reqs)} = {status_correct/len(reqs):.4f}')
    print(f'Exact step-array match: {exact}/{len(reqs)} = {exact/len(reqs):.4f}')
    print(f'Exact sequence (step fields, status excluded): {sequence_cases}/{len(reqs)} = {sequence_cases/len(reqs):.4f}')
    print(f'Step signatures: predicted={len(pred_steps)}, reference={len(gold_steps)}, matched={matched}')
    print(f'Step precision={precision:.4f}, recall={recall:.4f}, F1={f1:.4f}')
    print(f'Missing reference steps={missing}; extra predicted steps={extra}')
    print('Field accuracy at paired sequence positions:')
    for k in field_names: print(f'  {k}: {field_accuracy[k]}/{denom} = {field_accuracy[k]/max(1,denom):.4f}')
    print('Status confusion:')
    conf=Counter((gold[r['case_id']]['deletion_status'],predictions[r['case_id']]['deletion_status']) for r in reqs)
    for k,v in sorted(conf.items()): print(f'  reference={k[0]} predicted={k[1]}: {v}')
    # Three synthetic checks use small, deterministic helper behavior rather than the dataset labels.
    historical=engine.resolve({'email':'o.walker6695@yahoo.com','audit_at':'2026-09-01T00:00:00Z'})=='user_523'
    redacted=engine._resource_state({'category':'SUPPORT_MESSAGE','action':'REDACT','raw':{'requester_email':None,'requester_name':None,'requester_phone':None},'flat':''})=='REDACTED'
    active_flow=engine._resource_state({'category':'DATA_FLOW','action':'DISABLE','raw':{'enabled':True},'flat':'enabled true'})=='ACTIVE'
    restore_risk=engine._resource_state({'category':'BACKUP_ARCHIVE','action':'BLOCK','raw':{'restore_allowed':True},'flat':'restore_allowed true'})=='ACTIVE'
    checks=[
      ('password reset is not deletion', not engine._intent("I can't access my profile and need help resetting the login. Do not close the account.")),
      ('historical email alias resolves to stable identity', historical),
      ('retained support record with no direct identifiers is redacted', redacted),
      ('enabled connector is an active data flow', active_flow),
      ('backup with restore allowed is a restore risk', restore_risk),
      ('negated deletion remains not applicable', not engine._intent("Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything.")),
      ('marketing-only removal is not account deletion', not engine._intent('Please remove me from marketing lists only. I still want receipts and service messages for this account.')),
    ]
    print('Synthetic tests:')
    for name,ok in checks: print(f'  {"PASS" if ok else "FAIL"}: {name}')
    if not all(ok for _,ok in checks): sys.exit(1)
if __name__=='__main__': main()
