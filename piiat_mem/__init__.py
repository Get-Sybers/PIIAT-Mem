"""PIIAT-Mem — Put It In A Timeline (Memory).

Point it at a memory image; get a time-ordered timeline (CSV or JSON) built from
Volatility 3, including the custom DFIR plugins (windows.PIIAT_processes,
windows.PIIAT_registry) and the flat jsonl_dfir renderer. Runs the analysis inside a minimal hardened
container by default, or natively against an installed Volatility 3.
"""
__version__ = "0.2.0"
