"""Simulation harness for the Sealed Dispatch protocol (see ../../THREAT-MODEL.md).

Models the system at the protocol level (providers, registry, dispatch,
attackers) so the security metrics from THREAT-MODEL.md §6/§4.1 can be
measured without depending on any specific LLM agent framework. Wiring
this into LangGraph/AutoGen for a live demo is a separate, later step
that should not change any of these numbers.
"""
