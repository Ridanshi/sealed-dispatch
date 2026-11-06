"""Run every experiment in order and leave CSVs in results/.

Usage: python run_all.py
"""
import os
import runpy
import sys

EXPERIMENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "experiments")
sys.path.insert(0, EXPERIMENTS_DIR)

EXPERIMENT_FILES = [
    "exp1_baseline_vs_routejacking.py",
    "exp2_sealed_dispatch_defense.py",
    "exp3_latency_overhead.py",
    "exp4_pareto_committee_window.py",
    "exp5_sybil_flood.py",
    "exp6_slashing_condition.py",
    "exp7_real_threshold_bls_benchmark.py",
    "exp8_a4_authenticated_reveal.py",
    "exp9_committee_fault_tolerance.py",
    "exp10_factorial_ablation.py",
    "exp14_scale_and_adaptive.py",
    "exp15_defense_comparison.py",
    "exp17_correlated_and_proactive.py",
    "exp19_preference_mismatch.py",
]


def main():
    for fname in EXPERIMENT_FILES:
        path = os.path.join(EXPERIMENTS_DIR, fname)
        print(f"\n{'=' * 70}\nrunning {fname}\n{'=' * 70}")
        runpy.run_path(path, run_name="__main__")


if __name__ == "__main__":
    main()
