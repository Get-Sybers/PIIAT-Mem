"""PIIAT-Mem — Put It In A Timeline (Memory).

Point it at a memory image; get a **MITRE CAR** event store and timeline. The
pipeline is Plaso-shaped — Volatility 3 plugins (including the custom
windows.piiat.processes / windows.piiat.registry) extract raw records; a
normalization stage maps them to CAR objects/actions/properties; an enrichment
stage resolves process-context links (guid = the _EPROCESS offset — never the
reused PID); a SQLite store (car.db, the .plaso analogue) holds the finished CAR
events; and the outputs (wide JSONL timeline / per-object CSVs) are derived views
of the store. Runs the analysis inside a minimal hardened container by default,
or natively against an installed Volatility 3.
"""
__version__ = "0.3.0"
