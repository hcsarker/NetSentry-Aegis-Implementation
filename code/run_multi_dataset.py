import os
import json
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
import time

results = {}

# 1. UNSW-NB15 evaluation
print('--- Evaluating on UNSW-NB15 ---')
train_unsw = pd.read_csv('data/UNSW/unsw_train.csv')
test_unsw = pd.read_csv('data/UNSW/unsw_test.csv')

drop_cols = ['id', 'attack_cat', 'label']
cat_cols = ['proto', 'service', 'state']

X_tr = train_unsw.drop(columns=[c for c in drop_cols if c in train_unsw.columns])
y_tr = train_unsw['label'].values
X_te = test_unsw.drop(columns=[c for c in drop_cols if c in test_unsw.columns])
y_te = test_unsw['label'].values

X_all = pd.concat([X_tr, X_te], axis=0)
X_all_encoded = pd.get_dummies(X_all, columns=cat_cols, drop_first=True)
X_tr_enc = X_all_encoded.iloc[:len(X_tr)].values
X_te_enc = X_all_encoded.iloc[len(X_tr):].values

clf_unsw = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.15, n_jobs=-1, random_state=42, eval_metric='logloss')
clf_unsw.fit(X_tr_enc, y_tr)

t0 = time.time()
p_te = clf_unsw.predict_proba(X_te_enc)[:, 1]
inf_time = (time.time() - t0) / len(X_te_enc) * 1000
y_pred = (p_te >= 0.5).astype(int)

results['UNSW-NB15'] = {
    'dataset': 'UNSW-NB15',
    'n_train': len(X_tr),
    'n_test': len(X_te),
    'features': int(X_tr_enc.shape[1]),
    'accuracy': float(accuracy_score(y_te, y_pred)),
    'precision': float(precision_score(y_te, y_pred)),
    'recall': float(recall_score(y_te, y_pred)),
    'f1': float(f1_score(y_te, y_pred)),
    'roc_auc': float(roc_auc_score(y_te, p_te)),
    'latency_ms': float(inf_time)
}
print('UNSW Results:', results['UNSW-NB15'])

# 2. N-BaIoT evaluation (Danmini Doorbell)
print('--- Evaluating on N-BaIoT (Danmini Doorbell) ---')
df_benign = pd.read_csv('data/N-Baiot/1.benign.csv')
df_gafgyt = pd.read_csv('data/N-Baiot/1.gafgyt.combo.csv', nrows=25000)
df_mirai = pd.read_csv('data/N-Baiot/1.mirai.scan.csv', nrows=25000)

df_benign = df_benign.copy()
df_benign['label'] = 0
df_gafgyt = df_gafgyt.copy()
df_gafgyt['label'] = 1
df_mirai = df_mirai.copy()
df_mirai['label'] = 1

df_nb = pd.concat([df_benign.sample(n=min(len(df_benign), 35000), random_state=42),
                   df_gafgyt.sample(n=min(len(df_gafgyt), 20000), random_state=42),
                   df_mirai.sample(n=min(len(df_mirai), 20000), random_state=42)], axis=0).sample(frac=1.0, random_state=42)

X_nb = df_nb.drop(columns=['label']).values
y_nb = df_nb['label'].values

X_tr_nb, X_te_nb, y_tr_nb, y_te_nb = train_test_split(X_nb, y_nb, test_size=0.3, stratify=y_nb, random_state=42)

clf_nb = XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.15, n_jobs=-1, random_state=42, eval_metric='logloss')
clf_nb.fit(X_tr_nb, y_tr_nb)

t0 = time.time()
p_te_nb = clf_nb.predict_proba(X_te_nb)[:, 1]
inf_time_nb = (time.time() - t0) / len(X_te_nb) * 1000
y_pred_nb = (p_te_nb >= 0.5).astype(int)

results['N-BaIoT'] = {
    'dataset': 'N-BaIoT (Device 1 - Danmini Doorbell)',
    'n_train': len(X_tr_nb),
    'n_test': len(X_te_nb),
    'features': int(X_tr_nb.shape[1]),
    'accuracy': float(accuracy_score(y_te_nb, y_pred_nb)),
    'precision': float(precision_score(y_te_nb, y_pred_nb)),
    'recall': float(recall_score(y_te_nb, y_pred_nb)),
    'f1': float(f1_score(y_te_nb, y_pred_nb)),
    'roc_auc': float(roc_auc_score(y_te_nb, p_te_nb)),
    'latency_ms': float(inf_time_nb)
}
print('N-BaIoT Results:', results['N-BaIoT'])

# 3. CICIOT2023 evaluation
print('--- Evaluating on CICIOT2023 ---')
df_iot23 = pd.read_csv('data/CICIOT23/validation/validation.csv', nrows=50000)
y_iot = (df_iot23['label'].astype(str) != 'BenignTraffic').astype(int).values
print('CICIOT23 class counts: 0 =', int((y_iot == 0).sum()), ', 1 =', int((y_iot == 1).sum()))

X_iot = df_iot23.drop(columns=['label'])
X_iot = X_iot.select_dtypes(include=[np.number]).fillna(0).values

X_tr_iot, X_te_iot, y_tr_iot, y_te_iot = train_test_split(X_iot, y_iot, test_size=0.3, stratify=y_iot, random_state=42)

clf_iot = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.15, n_jobs=-1, random_state=42, eval_metric='logloss')
clf_iot.fit(X_tr_iot, y_tr_iot)

t0 = time.time()
p_te_iot = clf_iot.predict_proba(X_te_iot)[:, 1]
inf_time_iot = (time.time() - t0) / len(X_te_iot) * 1000
y_pred_iot = (p_te_iot >= 0.5).astype(int)

results['CICIOT2023'] = {
    'dataset': 'CICIOT2023 (IoT Network Traffic)',
    'n_train': len(X_tr_iot),
    'n_test': len(X_te_iot),
    'features': int(X_tr_iot.shape[1]),
    'accuracy': float(accuracy_score(y_te_iot, y_pred_iot)),
    'precision': float(precision_score(y_te_iot, y_pred_iot)),
    'recall': float(recall_score(y_te_iot, y_pred_iot)),
    'f1': float(f1_score(y_te_iot, y_pred_iot)),
    'roc_auc': float(roc_auc_score(y_te_iot, p_te_iot)),
    'latency_ms': float(inf_time_iot)
}
print('CICIOT2023 Results:', results['CICIOT2023'])

# 4. CICIDS2017 & NSL-KDD
if os.path.exists('results/cicids_results.json'):
    with open('results/cicids_results.json') as f:
        results['CICIDS2017'] = json.load(f)['XGBoost']

if os.path.exists('results/model_results.json'):
    with open('results/model_results.json') as f:
        results['NSL-KDD'] = json.load(f)['XGBoost']

os.makedirs('outputs', exist_ok=True)
with open('outputs/multi_dataset_benchmark_results.json', 'w') as f:
    json.dump(results, f, indent=2)

print('\n=== ALL DATASET BENCHMARK RESULTS SAVED ===')
