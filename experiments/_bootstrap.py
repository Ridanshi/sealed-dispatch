"""Shared sys.path bootstrap so experiment scripts can be run directly
(`python experiments/expN_....py`) without installing the package."""
import os
import sys

_EVAL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _EVAL_DIR not in sys.path:
    sys.path.insert(0, _EVAL_DIR)

RESULTS_DIR = os.path.join(_EVAL_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)
