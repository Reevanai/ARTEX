---
name: ledger-invariants
description: "Invoke this skill when the authorized target is a banking, payments, wallet, card-processing or core-banking API and the goal is to prove money-handling flaws: double spend under concurrency, broken idempotency, negative or sign-flipped amounts, rounding/FX leakage, cross-customer access to accounts, and step-up OTP without lockout. Every finding must be judged against a ledger invariant and a reconciliation view, not a response code."
---

# Ledger Invariant Testing (banking & payments)

Generic API testing asks whether a request was *accepted*. In a ledger the only question that matters is whether **money was conserved and moved only with authority**. This skill turns that into six invariants and a strict evidence rule: a finding exists only when a before/after reconciliation snapshot shows the invariant broken.

The deterministic version of this playbook ships as the `ledgerguard` binary (`cmd/ledgerguard`, package `ledgerguard`). Prefer running it first; use this skill to extend coverage to flows it does not model (UPI collect, card auth/capture/refund, standing instructions, interest accrual, reversals).

## Boundaries (non-negotiable)

- Engagement authorization reference recorded before the first request. UAT / sandbox / bank-provided cyber range preferred; production only with a written RoE and named test accounts.
- Use **only designated test identities and accounts**. The "victim" is a consenting test customer, never a real one.
- Smallest provable amount (₹1, one paise for rounding). Concurrency bursts of ≤ 8 requests. This is not a load test.
- Never brute-force an OTP to completion. Proving the absence of a lockout (11 failures, per PCI DSS 8.3.4) is sufficient.
- Ask the operator for a read-only reconciliation view (GL export, EOD recon file, read replica, journal topic). Without one, findings drop to "suspected" and must say so.

## The six invariants

| Id | Invariant | Probe | Typical root cause |
|---|---|---|---|
| conservation | Internal movements never change the system total per currency | FX/fee/interest round-trips at the minimum unit | Rounding in customer's favour, residue not booked to a GL |
| non_negative | No account below zero without an overdraft line | N concurrent full-balance debits | Check-then-debit outside one transaction (TOCTOU) |
| double_entry | Every txn's postings net to zero per currency | Inspect journal for one-legged postings after failures/timeouts | Partial commit, missing compensation on reversal |
| authority | Only the owner (or a mandate) moves or reads an account | Negative amount to a foreign destination; read foreign account; swap `from` in body | Signed amounts, ownership checked on path but not body |
| idempotency | One key → at most one posting set | Two in-flight requests with one key; same key, different payload | Non-atomic key reservation; key not caller-scoped or payload-bound |
| step_up_ceiling | Step-up auth locks after bounded failures | 11 wrong OTPs on one challenge | No attempt counter, counter per request not per challenge |

## Procedure

1. **Map money paths** (handoff from api-recon): every endpoint that creates a posting: transfer, payout, refund, reversal, FX, fee, cashback, interest, chargeback. Note amount fields, sign conventions, currency fields, idempotency headers.
2. **Snapshot** the reconciliation view. Record system totals per currency and the journal length.
3. **Run one probe**, then snapshot again. Diff with the invariant table. Never chain probes between snapshots; attribution must be unambiguous.
4. **Quantify**: convert the delta into rupee exposure (per event × realistic daily volume the operator supplies). Boards act on ₹, not CVSS.
5. **Map controls**: PCI DSS v4.0 6.2.4 / 7.2 / 8.3.4, RBI Master Direction on Digital Payment Security Controls (2021), RBI IT Governance Master Direction (2023), DPDP Act 2023 s.8(5), OWASP API Top 10 (2023). Mark mappings indicative.
6. **Retest the fix** against the same invariant. A fix is proven when the identical sequence leaves the snapshot diff empty.

## Finding quality gate

A ledger finding must include: the before and after snapshot totals, the exact request sequence (with timing for races), the identity used for each request, the invariant name, the rupee exposure and its assumptions, and the remediation pattern (conditional debit, atomic key reservation, unsigned amount + direction, bank-favoured rounding with residue GL, per-challenge lockout).
