# -*- coding: utf-8 -*-
"""Paired-by-seed 95% intervals for the comparisons drawn in the paper (mitigations, combined defense, blind candidacy).
Seeds 0-19, Bazaar pool of 50, worst case over the three attackers per seed. Run: python tests/paired_claims.py"""
import sys, statistics as st
sys.path.insert(0,'.')
from concurrent.futures import ProcessPoolExecutor
from sealed_dispatch_eval.runner import RunConfig, run
SEEDS=list(range(20)); ATT=("bucket_max","regression","feedback")
def one(c): return run(c)
def per_seed(ex, **kw):
    """per seed: worst-case (max over attackers) revenue, win rate and regret"""
    res={a:list(ex.map(one,[RunConfig(pool="bazaar",n_legit=50,attacker=a,seed=s,**kw) for s in SEEDS],chunksize=2)) for a in ATT}
    return [{k:max(res[a][i][k] for a in ATT) for k in ("revenue","win_rate","regret")} for i in range(len(SEEDS))]
def ci(d): m=st.mean(d); return m, 1.96*st.stdev(d)/len(d)**0.5
def paired(name, A, B, key):
    d=[a[key]-b[key] for a,b in zip(A,B)]; m,h=ci(d)
    print(f"  {name} [{key}]: mean diff {m:+.4f} 95% CI [{m-h:+.4f}, {m+h:+.4f}]  -> {'separated' if (m-h>0 or m+h<0) else 'NOT separated'}")
if __name__=="__main__":
    with ProcessPoolExecutor() as ex:
        plain=per_seed(ex,selection="all_scored",view="full")
        lot05=per_seed(ex,selection="all_scored",view="full",tau=0.05)
        lot10=per_seed(ex,selection="all_scored",view="full",tau=0.10)
        b10=per_seed(ex,selection="stake_m",view="coarse",m=10)
        b20=per_seed(ex,selection="stake_m",view="coarse",m=20)
        b10l=per_seed(ex,selection="stake_m",view="coarse",m=10,tau=0.05)
        print("lottery .10 (A) vs bounded m=20 (B): paper claims A lower revenue AND lower regret")
        paired("A-B",lot10,b20,"revenue"); paired("A-B",lot10,b20,"regret")
        print("lottery .05 vs plaintext: paper claims 61% revenue cut")
        paired("A-B",lot05,plain,"revenue")
        print("bounded m=10 + lottery vs bounded m=10 alone: paper says 'about the same regret', 'mechanisms overlap'")
        paired("A-B",b10l,b10,"revenue"); paired("A-B",b10l,b10,"regret")
        print("bounded m=10 regret vs lottery .05 regret: paper says nearly seven times")
        paired("A-B",b10,lot05,"regret")
        full=per_seed(ex,selection="stake_m",view="full"); coarse=per_seed(ex,selection="stake_m",view="coarse")
        fullp=per_seed(ex,selection="all_scored",view="full"); coarsep=per_seed(ex,selection="all_scored",view="coarse")
        print("blind candidacy (coarse A vs exact B), worst-case attacker per seed")
        paired("bounded A-B",coarse,full,"revenue"); paired("bounded A-B",coarse,full,"win_rate")
        paired("plaintext A-B",coarsep,fullp,"revenue"); paired("plaintext A-B",coarsep,fullp,"win_rate")
