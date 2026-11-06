"""LangGraph wiring for Sealed Dispatch (THREAT-MODEL.md §4).

This package is glue only: it puts dispatch_baseline / dispatch_sealed
from sealed_dispatch_eval.dispatch behind LangGraph nodes so an agent
graph can call them like any other tool-dispatch step. It must not
reimplement or shadow any protocol logic -- every security/latency
number produced by this graph should be reproducible by calling
sealed_dispatch_eval directly, as the experiments/ scripts already do.
If a change here ever changes a measured outcome, that's a bug in the
adapter, not a new result.
"""
