"""
policy_lib.py
--------------
Shared utilities for the policy-layer experiments (11_*).

The central question these utilities answer: given the SAME per-record
threat probabilities from the SAME detector, what does the enforcement
layer on top of it add? We therefore build device-level event streams out
of real per-record detector outputs, and run several enforcement policies
over identical streams (paired comparison, common random numbers):

    per_event   plain binary block: block the event if p >= tau (stateless)
    sticky      plain binary quarantine: block the device forever after the
                first event with p >= tau
    kofn        block while >= m of the last w events were flagged (p >= 0.5)
    ewma_sym    symmetric EWMA trust score, restrict when trust < theta
    trust       asymmetric EWMA trust score (NetSentry-Aegis), six tiers,
                restrict when trust < theta

All policies are vectorised over devices (rows) and run over a fixed
horizon of T steps (columns).
"""
import numpy as np

T_HORIZON = 60      # events per simulated device
T0 = 15             # step at which a compromised device turns malicious
BURST_LEN = 10      # length of a transient malicious burst
MIN_GROUP = 30      # min records for a service / attack type to be used when pinning

TIER_NAMES = ["Allow", "Monitor", "Re-authenticate", "Restrict", "Isolate", "Block"]


# ----------------------------------------------------------------------------
# Pools and stream construction
# ----------------------------------------------------------------------------
class Pool:
    """Per-record detector probabilities with labels (+ optional metadata)."""

    def __init__(self, probs, y, label=None, service=None, name="pool"):
        self.name = name
        self.p = np.asarray(probs, dtype=float)
        self.y = np.asarray(y).astype(int)
        self.benign_idx = np.where(self.y == 0)[0]
        self.attack_idx = np.where(self.y == 1)[0]
        self.label = None if label is None else np.asarray(label).astype(str)
        self.service = None if service is None else np.asarray(service).astype(str)

        self.svc_keys, self.svc_idx, self.svc_w = [], [], None
        if self.service is not None:
            for s in np.unique(self.service[self.benign_idx]):
                idx = self.benign_idx[self.service[self.benign_idx] == s]
                if len(idx) >= MIN_GROUP:
                    self.svc_keys.append(s)
                    self.svc_idx.append(idx)
            cnt = np.array([len(i) for i in self.svc_idx], dtype=float)
            self.svc_w = cnt / cnt.sum() if len(cnt) else None

        self.att_keys, self.att_idx = [], []
        if self.label is not None:
            for l in np.unique(self.label[self.attack_idx]):
                idx = self.attack_idx[self.label[self.attack_idx] == l]
                if len(idx) >= MIN_GROUP:
                    self.att_keys.append(l)
                    self.att_idx.append(idx)

    def stats(self, thr=0.5):
        pred = self.p >= thr
        return {
            "n": int(len(self.p)),
            "attack_share": float(self.y.mean()),
            "recall": float(pred[self.y == 1].mean()),
            "fpr": float(pred[self.y == 0].mean()),
        }


def _draw_pinned(groups, probs_weights, n_dev, T, rng):
    """For every device pick one group, then draw T record indices from it."""
    k = len(groups)
    choice = rng.choice(k, size=n_dev, p=probs_weights)
    out = np.empty((n_dev, T), dtype=int)
    for g in range(k):
        rows = np.where(choice == g)[0]
        if len(rows):
            out[rows] = rng.choice(groups[g], size=(len(rows), T))
    return out, choice


def build_stream(pool, scenario, n_dev, rng, mode="iid", T=T_HORIZON, t0=T0,
                 burst=BURST_LEN, duty=None):
    """Return (P, M, dev_attack_group) where P[n,T] are detector probabilities
    and M[n,T] marks truly malicious events.

    scenario: 'benign' | 'compromised' | 'burst' | 'duty'
    mode:     'iid'    events drawn independently from the whole pool
              'pinned' each device keeps ONE service (benign events) and ONE
                       attack type (malicious events), so detector errors are
                       correlated within a device, as they would be in practice
    """
    M = np.zeros((n_dev, T), dtype=bool)
    if scenario == "compromised":
        M[:, t0:] = True
    elif scenario == "burst":
        M[:, t0:t0 + burst] = True
    elif scenario == "duty":
        M[:, t0:] = rng.random((n_dev, T - t0)) < duty

    if mode == "iid" or pool.svc_w is None or not pool.att_keys:
        ben = rng.choice(pool.benign_idx, size=(n_dev, T))
        att = rng.choice(pool.attack_idx, size=(n_dev, T))
        dev_att = np.full(n_dev, -1)
    else:
        ben, _ = _draw_pinned(pool.svc_idx, pool.svc_w, n_dev, T, rng)
        w_att = np.full(len(pool.att_keys), 1.0 / len(pool.att_keys))
        att, dev_att = _draw_pinned(pool.att_idx, w_att, n_dev, T, rng)

    idx = np.where(M, att, ben)
    return pool.p[idx], M, dev_att


def make_streams(pool, mode, n_dev, seed, duty_levels=(0.1, 0.2, 0.3, 0.5, 0.75),
                 scenarios=("benign", "compromised", "burst", "duty")):
    """Pre-generate every scenario once so that all policies see identical streams."""
    ss = np.random.SeedSequence(seed)
    children = ss.spawn(1 + len(duty_levels) + 3)
    streams = {}
    i = 0
    for sc in ("benign", "compromised", "burst"):
        if sc in scenarios:
            streams[sc] = build_stream(pool, sc, n_dev, np.random.default_rng(children[i]), mode)
        i += 1
    if "duty" in scenarios:
        for f in duty_levels:
            streams[f"duty_{f}"] = build_stream(pool, "duty", n_dev,
                                                np.random.default_rng(children[i]), mode, duty=f)
            i += 1
    return streams


# ----------------------------------------------------------------------------
# Policies. Each returns (R, S): R[n,T] bool "restricted", S[n,T] severity in [0,1]
# ----------------------------------------------------------------------------
def trust_trajectory(P, eta_down, eta_up, start=100.0):
    n, T = P.shape
    out = np.empty((n, T))
    cur = np.full(n, start)
    for t in range(T):
        target = (1.0 - P[:, t]) * 100.0
        eta = np.where(target < cur, eta_down, eta_up)
        cur = cur + eta * (target - cur)
        out[:, t] = cur
    return out


def tier_index(trust, theta):
    """0 Allow (>=80) | 1 Monitor (>=60) | 2 Re-authenticate (>=theta) |
    3 Restrict (>=0.625*theta) | 4 Isolate (>=0.25*theta) | 5 Block.
    With theta=40 this reproduces the 80/60/40/25/10 boundaries in the paper."""
    idx = np.zeros(trust.shape, dtype=int)
    idx[trust < 80] = 1
    idx[trust < 60] = 2
    idx[trust < theta] = 3
    idx[trust < 0.625 * theta] = 4
    idx[trust < 0.25 * theta] = 5
    return idx


def pol_per_event(P, tau):
    R = P >= tau
    return R, R.astype(float)


def pol_sticky(P, tau):
    R = np.maximum.accumulate(P >= tau, axis=1)
    return R, R.astype(float)


def pol_kofn(P, w, m, tau=0.5):
    F = (P >= tau).astype(int)
    cs = np.cumsum(F, axis=1)
    win = cs.copy()
    win[:, w:] = cs[:, w:] - cs[:, :-w]
    R = win >= m
    return R, R.astype(float)


def pol_ewma(P, eta_down, eta_up, theta):
    trust = trust_trajectory(P, eta_down, eta_up)
    idx = tier_index(trust, theta)
    return idx >= 3, idx / 5.0


def make_policy(family, **kw):
    if family == "per_event":
        return lambda P: pol_per_event(P, kw["tau"])
    if family == "sticky":
        return lambda P: pol_sticky(P, kw["tau"])
    if family == "kofn":
        return lambda P: pol_kofn(P, kw["w"], kw["m"])
    if family == "ewma_sym":
        return lambda P: pol_ewma(P, kw["eta"], kw["eta"], kw["theta"])
    if family == "trust":
        return lambda P: pol_ewma(P, kw["eta_down"], kw["eta_up"], kw["theta"])
    raise ValueError(family)


# ----------------------------------------------------------------------------
# Per-device metrics
# ----------------------------------------------------------------------------
def device_metrics(R, S, M, kind, t0=T0, burst=BURST_LEN):
    """Return a dict of per-device arrays for one scenario."""
    n, T = R.shape
    out = {}
    if kind == "benign":
        out["ever_restricted"] = R.any(axis=1).astype(float)
        out["restricted_frac"] = R.mean(axis=1)
        out["severity"] = S.mean(axis=1)
        return out

    mal_cnt = M.sum(axis=1)
    has_mal = mal_cnt > 0
    leak = np.where(has_mal, ((~R) & M).sum(axis=1) / np.maximum(mal_cnt, 1), np.nan)
    out["leakage"] = leak

    first_mal = np.where(has_mal, M.argmax(axis=1), T)
    tt = np.arange(T)[None, :]
    after = tt >= first_mal[:, None]
    hit = R & after
    contained = hit.any(axis=1) & has_mal
    ttc = np.where(contained, hit.argmax(axis=1) - first_mal, T - first_mal)
    out["contained"] = np.where(has_mal, contained.astype(float), np.nan)
    out["ttc"] = np.where(has_mal, ttc.astype(float), np.nan)
    out["contained_5"] = np.where(has_mal, (contained & (ttc < 5)).astype(float), np.nan)

    ben_ev = ~M
    out["benign_event_restricted"] = np.where(
        ben_ev.sum(axis=1) > 0, (R & ben_ev).sum(axis=1) / np.maximum(ben_ev.sum(axis=1), 1), np.nan)

    if kind == "burst":
        e = t0 + burst
        post = R[:, e:]
        free = ~post
        has_free = free.any(axis=1)
        rec = np.where(has_free, free.argmax(axis=1), T - e)
        out["recovery_steps"] = rec.astype(float)
        out["post_burst_restricted_frac"] = post.mean(axis=1)
    return out


def evaluate_policy(policy, streams, which=None):
    """Run a policy over pre-generated streams; return {scenario: {metric: array}}."""
    res = {}
    for name, (P, M, _) in streams.items():
        if which is not None and name not in which:
            continue
        R, S = policy(P)
        kind = "benign" if name == "benign" else ("burst" if name == "burst" else "attack")
        res[name] = device_metrics(R, S, M, kind)
    return res


def mean_ci(x):
    x = np.asarray(x, dtype=float)
    x = x[~np.isnan(x)]
    if len(x) == 0:
        return float("nan"), float("nan")
    m = float(x.mean())
    h = float(1.96 * x.std(ddof=1) / np.sqrt(len(x))) if len(x) > 1 else 0.0
    return m, h


def summarize(res):
    """Collapse per-device arrays into {key: [mean, ci_halfwidth]} (+ median TTC)."""
    out = {}
    for sc, d in res.items():
        for k, v in d.items():
            out[f"{sc}.{k}"] = list(mean_ci(v))
        if "ttc" in d:
            out[f"{sc}.ttc_median"] = [float(np.nanmedian(d["ttc"])), 0.0]
    return out


def paired_diff(res_a, res_b, scenario, metric):
    """Mean and 95% CI of (A - B) over devices (streams are shared => paired)."""
    a, b = res_a[scenario][metric], res_b[scenario][metric]
    d = a - b
    return mean_ci(d)
