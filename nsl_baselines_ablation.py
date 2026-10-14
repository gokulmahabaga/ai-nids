import pandas as pd, numpy as np, sklearn, sys
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
print('sklearn',sklearn.__version__,'pandas',pd.__version__,'numpy',np.__version__,'python',sys.version.split()[0])
tr=pd.read_csv('/mnt/user-data/outputs/nsl_kdd_train.csv'); te=pd.read_csv('/mnt/user-data/outputs/nsl_kdd_test.csv')
cat=['protocol_type','service','flag']
feat=[c for c in tr.columns if c not in('label','difficulty')]
groups={
 'basic':['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent'],
 'content':['hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login'],
 'time_window':['count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate'],
 'host_window':[c for c in feat if c.startswith('dst_host')]}
assert sorted(sum(groups.values(),[]))==sorted(feat)
y=lambda d:(d.label=='attack').astype(int)
ytr,yte=y(tr),y(te)
def enc(cols,fit_on):
    e=OrdinalEncoder(handle_unknown='use_encoded_value',unknown_value=-1).fit(fit_on[cat])
    return e
def prep(cols,mode):
    A,B=tr[cols].copy(),te[cols].copy()
    cc=[c for c in cat if c in cols]
    if cc:
        fit=pd.concat([tr[cc],te[cc]]) if mode=='union' else tr[cc]
        e=OrdinalEncoder(handle_unknown='use_encoded_value',unknown_value=-1).fit(fit)
        A[cc]=e.transform(tr[cc]);B[cc]=e.transform(te[cc])
    return A,B
def ev(model,cols,mode='train',seeds=(0,)):
    A,B=prep(cols,mode);r=[]
    for s in seeds:
        m=model(s).fit(A,ytr);p=m.predict(B)
        pr,rc,f,_=precision_recall_fscore_support(yte,p,labels=[1],zero_division=0)
        r.append((accuracy_score(yte,p),pr[0],rc[0],f[0]))
    r=np.array(r);return r.mean(0),r.std(0)
rf=lambda s:RandomForestClassifier(n_estimators=200,max_depth=15,random_state=s,class_weight='balanced',n_jobs=-1)
seeds=range(5)
print('\n== Item 5: encoder fit on train+test union vs train only (RF, 5 seeds) ==')
for mode in['union','train']:
    m,sd=ev(rf,feat,mode,seeds);print(mode,'acc %.4f±%.4f  atk P %.3f R %.3f F1 %.3f'%(m[0],sd[0],m[1],m[2],m[3]))
print('\n== Item 6: baselines (train-only encoding) ==')
for n,mk in[('Majority(attack)',None),('Decision tree d=15',lambda s:DecisionTreeClassifier(max_depth=15,random_state=s,class_weight='balanced')),
 ('Logistic regression',lambda s:make_pipeline(StandardScaler(),LogisticRegression(max_iter=2000,class_weight='balanced'))),('Random Forest',rf)]:
    if mk is None:
        p=np.ones(len(yte));print(n,'acc %.4f'%accuracy_score(yte,p));continue
    m,sd=ev(mk,feat,'train',seeds if n=='Random Forest' else (0,));print(n,'acc %.4f  atk P %.3f R %.3f F1 %.3f'%tuple(m))
# rule: serror_rate>0.5 or count>... simple threshold
p=((te.serror_rate>0.5)|(te.dst_host_serror_rate>0.5)).astype(int)
pr,rc,f,_=precision_recall_fscore_support(yte,p,labels=[1],zero_division=0)
print('Rule serror_rate>0.5 or dst_host_serror_rate>0.5: acc %.4f P %.3f R %.3f'%(accuracy_score(yte,p),pr[0],rc[0]))
print('\n== Item 7: feature-group ablation (RF, 5 seeds, mean±sd acc; atk recall) ==')
full=feat
m,sd=ev(rf,full,'train',seeds);print('all 41            acc %.4f±%.4f R %.3f'%(m[0],sd[0],m[2]))
for g in groups:
    cols=[c for c in feat if c not in groups[g]];m,sd=ev(rf,cols,'train',seeds);print('drop %-12s acc %.4f±%.4f R %.3f'%(g,m[0],sd[0],m[2]))
agg=groups['time_window']+groups['host_window']
cols=[c for c in feat if c not in agg];m,sd=ev(rf,cols,'train',seeds);print('drop BOTH windows acc %.4f±%.4f R %.3f'%(m[0],sd[0],m[2]))
cols=agg;m,sd=ev(rf,cols,'train',seeds);print('ONLY windows      acc %.4f±%.4f R %.3f'%(m[0],sd[0],m[2]))
