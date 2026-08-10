# Synthetic federated identity demo

Run:

```text
python ndi_demo.py
```

The program stays open until `0` is selected. It can show:

- the separate National Insurance and Residency records;
- a concise result for Ada's positive check and Ben's negative check;
- a concise authenticated presentation summary received and checked by the relying party;
- a chronological audit log of scheme trust changes; and
- a read-only integrity view of the tamper-evident ledger behind that log.

Ada has an NI number and UK residency. Ben has UK residency but no NI number.
The relying party receives the derived Boolean result and protocol metadata,
not those raw records.

The last successful RP result remains available until another successful check
replaces it or the program closes.

The interactive check uses `HolderWallet`. `InclusionAssistedRoute` remains as
a diagram class and is exercised only by its equivalence test.

The implementation still contains exactly the fourteen Figure 3 classes and
fourteen direct component relationships. The structural pytest checks this
mapping without adding a class-map screen to the operator menu.

The demonstrator uses generated per-run secrets and domain-separated
HMAC-SHA256 messages. Provider assertions are checked against registered key
IDs, trust revisions, assurance levels and validity periods. Verification
rechecks RP policy, requires the exact provider evidence, obtains fresh
authenticated record status and rejects replay. Assurance events are hash
chained and HMAC authenticated; the Auditor pins the observed chain head for
the current program session.

The command-line program displays the current in-memory audit log and the
session-bound integrity state of its ledger.
Tampering, rehashing, rollback and persistence scenarios remain in the pytest
suite rather than being repeated in the operator menu.

Run the tests:

```text
python -m pip install pytest
python -m pytest
```

All seventeen tests are in `tests/test_ndi_demo.py`.

This remains a single-process structural demonstrator using synthetic records
and symmetric HMAC secrets. It does not create organisational separation,
asymmetric signatures, zero-knowledge proofs, network resilience or a legal
right-to-work decision.

The module documentation at the top of `ndi_demo.py` lists the official
Python manuals, standards and primary secure-audit paper supporting the
implemented mechanisms. Short citation keys in relevant docstrings refer back
to that list. These references explain the selected mechanisms; they do not
turn the demonstrator into a production security system or a statutory check.
