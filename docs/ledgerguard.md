# LedgerGuard: money-invariant assurance for banking stacks

Banking platforms sell the *rails*. LedgerGuard is not another set of rails: it is the
assurance layer that continuously checks a bank's own rails and proves whether **money can
appear, disappear, or move without authority**. The goal is to *secure* banking systems,
not to become one.

## Why invariants, not vulnerabilities

Scanners report injection and header issues. The losses that matter to banks (double
spends, retry double-debits, rounding salami, sign-flip pulls, step-up bypass) are
*business-logic* failures that often return a normal `200 OK`. LedgerGuard judges every
test sequence against a **read-only reconciliation oracle** and only raises a finding when
a ledger invariant observably breaks:

| Invariant | Meaning |
|---|---|
| `conservation` | internal movements never change the system total per currency |
| `non_negative` | no account goes below zero without an overdraft line |
| `authority` | only the owner can read or move an account |
| `idempotency` | one idempotency key yields at most one posting set |
| `step_up_ceiling` | step-up OTP locks after a bounded number of failures |

Each finding carries the captured HTTP exchanges, the rupee exposure, the CWE, the fix
pattern, and the controls it maps to (PCI DSS v4.0, RBI Digital Payment Security Controls,
RBI IT Governance 2023, DPDP Act 2023, OWASP API Top 10). Mappings are indicative and are
meant to be validated by the bank's compliance function.

## Safety brakes

- Refuses to run without an engagement authorization reference.
- Host allowlist: the base URL must be in the declared scope; redirects are never followed.
- Hard request budget (default 400); concurrency bursts capped at 6 — this is not a load test.
- Uses only designated test identities/accounts and the smallest provable amounts.
- Proves the absence of an OTP lockout with a bounded number of failures; never brute-forces to completion.

## Try it

```bash
go run ./cmd/artex-bankrange -addr 127.0.0.1:9900 &             # vulnerable practice bank
go run ./cmd/artex-bankrange -addr 127.0.0.1:9901 -hardened &   # same API, fixed
go run ./cmd/ledgerguard -target http://127.0.0.1:9900 -auth ENG-DEMO-001 -out demo/vulnerable
go run ./cmd/ledgerguard -target http://127.0.0.1:9901 -auth ENG-DEMO-001 -out demo/hardened
```

Measured on this checkout:

| Target | Grade | Findings | Money at risk (modelled) | Requests |
|---|---|---|---|---|
| bankrange (vulnerable) | F (0/100) | 6 (3 critical, 3 high) | ₹41,85,037.50 | 50 |
| bankrange (hardened) | A (100/100) | 0 | ₹0.00 | 25 |

The exit code is `2` when any invariant breaks, so the same command can gate a CI/CD
release of a payments service.

## Pointing it at an authorized real system

Supply a JSON profile (the fields of `ledgerguard.Profile`): base URL, allowed hosts, test
tokens for the `attacker` / `victim` / `auditor` roles, the designated test account ids,
the money-moving endpoint paths, and the read-only reconciliation path. Then:

```bash
go run ./cmd/ledgerguard -profile bank.json -auth ENG-2026-014 -out reports/acme
```

The reconciliation path should point at a read-only GL/EOD export, read replica, or
journal feed. LedgerGuard never needs write access to the ledger to judge an invariant.
Extend coverage to flows the bundled probes don't model (UPI collect, card
auth/capture/refund, standing instructions, reversals) with the `ledger-invariants` skill.
