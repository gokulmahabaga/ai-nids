#!/usr/bin/env python3
"""
eval_sessions.py -- session-level evaluation for the NIDS paper.

Train on some capture sessions, test on completely different ones (no flow from a
test session is ever seen in training). Label comes from the FILE NAME:
a name containing "attack" -> portscan, containing "normal" -> normal.

Usage:
  python3 eval_sessions.py --train attack_flows4.csv normal_flows4.csv \
                           --test  new_attack1.csv new_normal1.csv new_attack2.csv new_normal2.csv
"""
import argparse, os
import numpy as np, pandas as pd
from pandas.api.types import is_numeric_dtype
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

DROP = {"label","difficulty","src_ip","dst_ip","src_port","dst_port"}

def load(paths):
    parts=[]
    for p in paths:
        n=os.path.basename(p).lower()
        d=pd.read_csv(p)
        if "attack" in n: d["label"]="portscan"
        elif "normal" in n: d["label"]="normal"
        else: raise SystemExit(f"{p}: file name must contain 'attack' or 'normal'")
        d["session"]=n; parts.append(d)
    return pd.concat(parts,ignore_index=True)

ap=argparse.ArgumentParser()
ap.add_argument("--train",nargs="+",required=True); ap.add_argument("--test",nargs="+",required=True)
ap.add_argument("--seeds",type=int,default=5)
a=ap.parse_args()
tr,te=load(a.train),load(a.test)
feats=[c for c in tr.columns if c not in DROP and c!="session"]
for c in feats:
    if not is_numeric_dtype(tr[c]): raise SystemExit(f"non-numeric feature {c}")
print("TRAIN",tr.label.value_counts().to_dict(),"| TEST",te.label.value_counts().to_dict())
print("features:",feats)
print("overlap of test sessions with train files:",set(tr.session)&set(te.session) or "none")
accs=[]
for s in range(a.seeds):
    m=RandomForestClassifier(n_estimators=200,max_depth=15,random_state=s,class_weight="balanced").fit(tr[feats],tr.label)
    p=m.predict(te[feats]); accs.append(accuracy_score(te.label,p))
    if s==0:
        print("\n== seed 0 =="); print(classification_report(te.label,p,digits=3))
        print(pd.DataFrame(confusion_matrix(te.label,p,labels=["normal","portscan"]),index=["normal","portscan"],columns=["normal","portscan"]))
        print("\nper test session accuracy:"); te["pred"]=p
        print(te.groupby("session").apply(lambda g:(g.pred==g.label).mean(),include_groups=False).round(3).to_string())
        print("\nfeature importances:"); print(pd.Series(m.feature_importances_,index=feats).sort_values(ascending=False).round(3).to_string())
print(f"\naccuracy over {a.seeds} seeds: {np.mean(accs):.4f} +/- {np.std(accs):.4f}")

# ---- baselines on the same unseen test sessions ----
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import precision_recall_fscore_support
def rep(name,pred):
    p,r,f,_=precision_recall_fscore_support(te.label,pred,labels=["portscan"],zero_division=0)
    print(f"{name:<44} acc {accuracy_score(te.label,pred):.3f}  scan P {p[0]:.3f} R {r[0]:.3f} F1 {f[0]:.3f}")
print("\n== BASELINES on the same test sessions ==")
rep("Always 'normal'",np.array(["normal"]*len(te)))
if {"syn_count","ack_count"}<=set(feats):
    rep("SYN rule (syn>5 and ack<0.5*syn)",np.where((te.syn_count>5)&(te.ack_count<te.syn_count*0.5),"portscan","normal"))
if "src_distinct_ports" in feats:
    for n in (5,10,20,50):
        rep(f"Port-fan-out rule (src_distinct_ports > {n})",np.where(te.src_distinct_ports>n,"portscan","normal"))
per_flow=[c for c in feats if not c.startswith("src_")]
for name,cols in (("Decision tree, per-flow features only",per_flow),("Decision tree, all features",feats)):
    d=DecisionTreeClassifier(max_depth=15,random_state=0,class_weight="balanced").fit(tr[cols],tr.label); rep(name,d.predict(te[cols]))
l=make_pipeline(StandardScaler(),LogisticRegression(max_iter=2000,class_weight="balanced")).fit(tr[feats],tr.label); rep("Logistic regression, all features",l.predict(te[feats]))
m=RandomForestClassifier(n_estimators=200,max_depth=15,random_state=0,class_weight="balanced").fit(tr[per_flow],tr.label); rep("Random Forest, per-flow features only",m.predict(te[per_flow]))
m=RandomForestClassifier(n_estimators=200,max_depth=15,random_state=0,class_weight="balanced").fit(tr[feats],tr.label); rep("Random Forest, all features (proposed)",m.predict(te[feats]))
