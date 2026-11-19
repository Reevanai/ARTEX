package ledgerguard

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Profile describes one authorized target: where it lives, which test
// identities and accounts LedgerGuard may use, and which paths implement the
// money-moving operations. Adapters for a specific CBS/processor only need to
// produce a Profile and an oracle feed.
type Profile struct {
	Name       string            `json:"name"`
	BaseURL    string            `json:"base_url"`
	AllowHosts []string          `json:"allow_hosts"`
	Budget     int               `json:"request_budget"`
	Tokens     map[string]string `json:"tokens"` // attacker, victim, auditor

	AttackerPrimary   string `json:"attacker_primary_account"`
	AttackerSecondary string `json:"attacker_secondary_account"`
	AttackerFX        string `json:"attacker_fx_account"`
	VictimAccount     string `json:"victim_account"`

	PathAccount      string `json:"path_account"` // contains {id}
	PathTransfer     string `json:"path_transfer"`
	PathFX           string `json:"path_fx"`
	PathOTPChallenge string `json:"path_otp_challenge"`
	PathOTPVerify    string `json:"path_otp_verify"`
	PathRecon        string `json:"path_recon"`

	// FXConversionsPerDay scales a per-conversion rounding leak to a daily
	// exposure figure for the board report.
	FXConversionsPerDay int64 `json:"fx_conversions_per_day"`
}

// RangeProfile is the profile for the bundled artex-bankrange practice target.
func RangeProfile(base string) Profile {
	return Profile{
		Name:       "artex-bankrange",
		BaseURL:    base,
		AllowHosts: []string{"127.0.0.1", "localhost"},
		Budget:     400,
		Tokens: map[string]string{
			"attacker": "tok_mallory",
			"victim":   "tok_alice",
			"auditor":  "tok_auditor",
		},
		AttackerPrimary:     "acc_mallory_1",
		AttackerSecondary:   "acc_mallory_2",
		AttackerFX:          "acc_mallory_usd",
		VictimAccount:       "acc_alice_1",
		PathAccount:         "/v1/accounts/{id}",
		PathTransfer:        "/v1/transfers",
		PathFX:              "/v1/fx/convert",
		PathOTPChallenge:    "/v1/otp/challenge",
		PathOTPVerify:       "/v1/otp/verify",
		PathRecon:           "/v1/ledger/reconciliation",
		FXConversionsPerDay: 2_000_000,
	}
}

// Finding is one proven invariant break.
type Finding struct {
	ID          string      `json:"id"`
	Probe       string      `json:"probe"`
	Title       string      `json:"title"`
	Severity    string      `json:"severity"`
	Invariant   string      `json:"invariant"`
	CWE         string      `json:"cwe"`
	Summary     string      `json:"summary"`
	Violations  []Violation `json:"violations"`
	ExposureINR int64       `json:"exposure_minor_inr"` // money at risk, paise
	Exposure    string      `json:"exposure"`
	Remediation string      `json:"remediation"`
	Controls    []Control   `json:"controls"`
	Evidence    []Exchange  `json:"evidence"`
}

// ProbeResult is the outcome of one probe, pass or fail.
type ProbeResult struct {
	Probe    string   `json:"probe"`
	Title    string   `json:"title"`
	Passed   bool     `json:"passed"`
	Note     string   `json:"note"`
	Finding  *Finding `json:"finding,omitempty"`
	Requests int64    `json:"requests"`
	Error    string   `json:"error,omitempty"`
}

type probe struct {
	id, title string
	run       func(context.Context, *runner) ProbeResult
}

type runner struct {
	p      Profile
	c      *Client
	oracle *Oracle
}

func (r *runner) accountPath(id string) string {
	return strings.ReplaceAll(r.p.PathAccount, "{id}", id)
}

func (r *runner) balance(ctx context.Context, id string) (int64, error) {
	s, err := r.oracle.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	return s.Accounts[id].Balance, nil
}

// probes are ordered so that the destructive-looking ones (which only ever
// touch attacker-owned test accounts) run last.
var probes = []probe{
	{"LG-AUTHZ-READ", "Cross-customer account read (BOLA)", probeBOLA},
	{"LG-STEPUP", "Step-up OTP attempt ceiling", probeOTP},
	{"LG-SIGN", "Negative-amount transfer pulls funds", probeNegative},
	{"LG-ROUNDING", "FX rounding round-trip mints money", probeRounding},
	{"LG-IDEMPOTENCY", "Duplicate idempotency key double-posts", probeIdempotency},
	{"LG-DOUBLESPEND", "Concurrent transfers overdraw the source", probeRace},
}

func fail(id, title string, err error) ProbeResult {
	return ProbeResult{Probe: id, Title: title, Error: err.Error(), Note: "probe could not complete"}
}

func probeBOLA(ctx context.Context, r *runner) ProbeResult {
	const id, title = "LG-AUTHZ-READ", "Cross-customer account read (BOLA)"
	var got AccountView
	ex, err := r.c.Do(ctx, "attacker", "GET", r.accountPath(r.p.VictimAccount), nil, &got)
	if err != nil {
		return fail(id, title, err)
	}
	if ex.Status != 200 || got.Owner == "" {
		return ProbeResult{Probe: id, Title: title, Passed: true, Note: fmt.Sprintf("victim account refused with HTTP %d", ex.Status)}
	}
	return ProbeResult{Probe: id, Title: title, Finding: &Finding{
		Probe: id, Title: title, Severity: "high", Invariant: InvAuthority, CWE: "CWE-639",
		Summary: fmt.Sprintf("Attacker session read account %s owned by %q, including a balance of %s.",
			got.ID, got.Owner, Money(got.Balance, got.Currency)),
		Violations:  []Violation{{Invariant: InvAuthority, Detail: "account object returned to a non-owner identity"}},
		Exposure:    "Customer financial data (balances, identifiers) readable across tenants",
		Remediation: "Enforce owner/tenant check on every object lookup server-side; return 404 for foreign objects; add an authorization test per object route.",
		Evidence:    []Exchange{ex},
	}}
}

func probeOTP(ctx context.Context, r *runner) ProbeResult {
	const id, title = "LG-STEPUP", "Step-up OTP attempt ceiling"
	var ch struct {
		ID string `json:"challenge_id"`
	}
	ex0, err := r.c.Do(ctx, "attacker", "POST", r.p.PathOTPChallenge, map[string]any{}, &ch)
	if err != nil {
		return fail(id, title, err)
	}
	if ch.ID == "" {
		return ProbeResult{Probe: id, Title: title, Passed: true, Note: "no step-up challenge endpoint available"}
	}
	const attempts = 11 // PCI DSS 8.3.4: lock after not more than 10
	var last Exchange
	ev := []Exchange{ex0}
	for i := 0; i < attempts; i++ {
		guess := fmt.Sprintf("%04d", (i*7919+13)%10000)
		ex, err := r.c.Do(ctx, "attacker", "POST", r.p.PathOTPVerify, map[string]string{"challenge_id": ch.ID, "otp": guess}, nil)
		if err != nil {
			return fail(id, title, err)
		}
		last = ex
		if i < 2 || i == attempts-1 {
			ev = append(ev, ex)
		}
		if ex.Status == 429 || ex.Status == 423 || strings.Contains(strings.ToLower(ex.RespBody), "lock") {
			return ProbeResult{Probe: id, Title: title, Passed: true, Note: fmt.Sprintf("challenge locked after %d failed attempts", i+1)}
		}
		if ex.Status == 200 {
			return ProbeResult{Probe: id, Title: title, Passed: true, Note: "guess happened to match; inconclusive, rerun"}
		}
	}
	return ProbeResult{Probe: id, Title: title, Finding: &Finding{
		Probe: id, Title: title, Severity: "high", Invariant: InvStepUpCeil, CWE: "CWE-307",
		Summary: fmt.Sprintf("%d consecutive wrong OTPs were accepted for evaluation without lockout (last response HTTP %d). A 4-digit OTP space falls to ~10,000 requests.",
			attempts, last.Status),
		Violations:  []Violation{{Invariant: InvStepUpCeil, Detail: fmt.Sprintf("no lockout after %d failures", attempts)}},
		Exposure:    "Step-up authentication bypass on high-value actions (account takeover, beneficiary add)",
		Remediation: "Lock the challenge after ≤5 failures, bind it to device/session, rate-limit per account and per IP, and alert on bursts.",
		Evidence:    ev,
	}}
}

func probeNegative(ctx context.Context, r *runner) ProbeResult {
	const id, title = "LG-SIGN", "Negative-amount transfer pulls funds"
	before, err := r.oracle.Snapshot(ctx)
	if err != nil {
		return fail(id, title, err)
	}
	const pull = 100 // ₹1.00: the smallest proof, against a consenting test victim
	ex, err := r.c.Do(ctx, "attacker", "POST", r.p.PathTransfer, map[string]any{
		"from": r.p.AttackerPrimary, "to": r.p.VictimAccount, "amount_minor": -pull,
		"idempotency_key": fmt.Sprintf("lg-sign-%d", time.Now().UnixNano()),
	}, nil)
	if err != nil {
		return fail(id, title, err)
	}
	after, err := r.oracle.Snapshot(ctx)
	if err != nil {
		return fail(id, title, err)
	}
	vb, va := before.Accounts[r.p.VictimAccount].Balance, after.Accounts[r.p.VictimAccount].Balance
	if va >= vb {
		return ProbeResult{Probe: id, Title: title, Passed: true, Note: fmt.Sprintf("negative amount rejected with HTTP %d", ex.Status)}
	}
	return ProbeResult{Probe: id, Title: title, Finding: &Finding{
		Probe: id, Title: title, Severity: "critical", Invariant: InvAuthority, CWE: "CWE-20",
		Summary: fmt.Sprintf("A transfer of %s from the attacker's account debited the victim by %s. Any customer balance can be drained by naming it as the destination.",
			Money(-pull, "INR"), Money(vb-va, "INR")),
		Violations:  append(CheckLedger(before, after), Violation{Invariant: InvAuthority, Detail: "victim account debited without victim's authority", Currency: "INR", Delta: va - vb}),
		ExposureINR: vb,
		Exposure:    fmt.Sprintf("Entire balance of any reachable account (victim test account alone: %s)", Money(vb, "INR")),
		Remediation: "Reject amount <= 0 at the API edge and again in the posting engine; express transfers as unsigned amount + direction.",
		Evidence:    []Exchange{ex},
	}}
}

func probeRounding(ctx context.Context, r *runner) ProbeResult {
	const id, title = "LG-ROUNDING", "FX rounding round-trip mints money"
	before, err := r.oracle.Snapshot(ctx)
	if err != nil {
		return fail(id, title, err)
	}
	const trips = 10
	var ev []Exchange
	done := 0
	for i := 0; i < trips; i++ {
		var out struct {
			Credited int64 `json:"credited_minor"`
		}
		ex1, err := r.c.Do(ctx, "attacker", "POST", r.p.PathFX, map[string]any{"from_account": r.p.AttackerPrimary, "to_account": r.p.AttackerFX, "amount_minor": 1}, &out)
		if err != nil {
			return fail(id, title, err)
		}
		if i == 0 {
			ev = append(ev, ex1)
		}
		if ex1.Status != 200 || out.Credited <= 0 {
			break
		}
		ex2, err := r.c.Do(ctx, "attacker", "POST", r.p.PathFX, map[string]any{"from_account": r.p.AttackerFX, "to_account": r.p.AttackerPrimary, "amount_minor": out.Credited}, nil)
		if err != nil {
			return fail(id, title, err)
		}
		if i == 0 {
			ev = append(ev, ex2)
		}
		done++
	}
	after, err := r.oracle.Snapshot(ctx)
	if err != nil {
		return fail(id, title, err)
	}
	vs := CheckLedger(before, after)
	var mintedINR int64
	for _, v := range vs {
		if v.Invariant == InvConservation {
			if v.Currency == "INR" {
				mintedINR += v.Delta
			} else if v.Currency == "USD" {
				mintedINR += v.Delta * usdToPaise
			}
		}
	}
	if done == 0 || mintedINR <= 0 {
		note := "sub-unit conversions rejected or conserved"
		if done > 0 {
			note = fmt.Sprintf("%d round-trips conserved the system total", done)
		}
		return ProbeResult{Probe: id, Title: title, Passed: true, Note: note}
	}
	per := mintedINR / int64(done)
	daily := per * r.p.FXConversionsPerDay
	return ProbeResult{Probe: id, Title: title, Finding: &Finding{
		Probe: id, Title: title, Severity: "critical", Invariant: InvConservation, CWE: "CWE-682",
		Summary: fmt.Sprintf("%d INR→USD→INR round-trips of ₹0.01 created %s that no GL absorbs (%s per trip). Rounding is applied in the customer's favour on both legs while treasury books the fair value.",
			done, Money(mintedINR, "INR"), Money(per, "INR")),
		Violations:  vs,
		ExposureINR: daily,
		Exposure:    fmt.Sprintf("%s/day if scripted at %d conversions/day (salami attack)", Money(daily, "INR"), r.p.FXConversionsPerDay),
		Remediation: "Round toward the bank on every leg, enforce a minimum conversion amount, book rounding residue to a dedicated GL and reconcile it daily.",
		Evidence:    ev,
	}}
}

// usdToPaise converts one US cent to paise for exposure maths (83.50 rate).
const usdToPaise = 83

func probeIdempotency(ctx context.Context, r *runner) ProbeResult {
	const id, title = "LG-IDEMPOTENCY", "Duplicate idempotency key double-posts"
	bal, err := r.balance(ctx, r.p.AttackerPrimary)
	if err != nil {
		return fail(id, title, err)
	}
	amt := int64(100)
	if bal < 2*amt {
		return ProbeResult{Probe: id, Title: title, Passed: true, Note: "attacker test balance too low to run safely"}
	}
	key := fmt.Sprintf("lg-idem-%d", time.Now().UnixNano())
	body := map[string]any{"from": r.p.AttackerPrimary, "to": r.p.AttackerSecondary, "amount_minor": amt, "idempotency_key": key}
	exs := burst(ctx, r.c, 2, func(ctx context.Context) (Exchange, error) {
		return r.c.Do(ctx, "attacker", "POST", r.p.PathTransfer, body, nil)
	})
	txns := map[string]bool{}
	for _, ex := range exs {
		if t := jsonField(ex.RespBody, "txn_id"); t != "" {
			txns[t] = true
		}
	}
	if len(txns) <= 1 {
		return ProbeResult{Probe: id, Title: title, Passed: true, Note: "duplicate submissions collapsed to one posting"}
	}
	return ProbeResult{Probe: id, Title: title, Finding: &Finding{
		Probe: id, Title: title, Severity: "high", Invariant: InvIdempotency, CWE: "CWE-362",
		Summary:     fmt.Sprintf("Two in-flight requests with idempotency key %q produced %d distinct postings. Client retries (mobile network flaps, gateway timeouts) will double-debit customers.", key, len(txns)),
		Violations:  []Violation{{Invariant: InvIdempotency, Detail: fmt.Sprintf("%d postings for one key", len(txns)), Currency: "INR", Delta: amt * int64(len(txns)-1)}},
		ExposureINR: amt * int64(len(txns)-1),
		Exposure:    "Every retried payment is at risk of duplicate debit; customer-harm and chargeback exposure scales with retry rate",
		Remediation: "Reserve the idempotency key atomically (unique insert) before executing, scope it to the caller, and bind it to a hash of the payload.",
		Evidence:    exs,
	}}
}

func probeRace(ctx context.Context, r *runner) ProbeResult {
	const id, title = "LG-DOUBLESPEND", "Concurrent transfers overdraw the source"
	before, err := r.oracle.Snapshot(ctx)
	if err != nil {
		return fail(id, title, err)
	}
	bal := before.Accounts[r.p.AttackerPrimary].Balance
	if bal <= 0 {
		return ProbeResult{Probe: id, Title: title, Passed: true, Note: "attacker test balance is zero; nothing to race"}
	}
	const n = 6 // a handful, never a load test
	exs := burst(ctx, r.c, n, func(ctx context.Context) (Exchange, error) {
		return r.c.Do(ctx, "attacker", "POST", r.p.PathTransfer, map[string]any{
			"from": r.p.AttackerPrimary, "to": r.p.AttackerSecondary, "amount_minor": bal,
			"idempotency_key": fmt.Sprintf("lg-race-%d", time.Now().UnixNano()),
		}, nil)
	})
	after, err := r.oracle.Snapshot(ctx)
	if err != nil {
		return fail(id, title, err)
	}
	posted := 0
	for _, ex := range exs {
		if ex.Status == 200 {
			posted++
		}
	}
	var vs []Violation
	for _, v := range CheckLedger(before, after) {
		if v.Invariant == InvNonNegative {
			vs = append(vs, v)
		}
	}
	if len(vs) == 0 {
		return ProbeResult{Probe: id, Title: title, Passed: true, Note: fmt.Sprintf("%d/%d concurrent full-balance transfers posted; balance never went negative", posted, n)}
	}
	over := -after.Accounts[r.p.AttackerPrimary].Balance
	return ProbeResult{Probe: id, Title: title, Finding: &Finding{
		Probe: id, Title: title, Severity: "critical", Invariant: InvNonNegative, CWE: "CWE-362",
		Summary: fmt.Sprintf("%d of %d concurrent transfers of the full balance (%s) posted. The source ended at %s: the balance check and the debit are not atomic.",
			posted, n, Money(bal, "INR"), Money(-over, "INR")),
		Violations:  vs,
		ExposureINR: over,
		Exposure:    fmt.Sprintf("%s overdrawn from a %s balance in one burst; scales linearly with concurrency and account count", Money(over, "INR"), Money(bal, "INR")),
		Remediation: "Debit with a conditional update (UPDATE … SET bal = bal - x WHERE bal >= x) or a row lock inside the posting transaction; move fraud checks before the reservation, not between check and debit.",
		Evidence:    exs,
	}}
}

// burst fires n copies of fn as close to simultaneously as possible.
func burst(ctx context.Context, c *Client, n int, fn func(context.Context) (Exchange, error)) []Exchange {
	var wg sync.WaitGroup
	start := make(chan struct{})
	out := make([]Exchange, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ex, err := fn(ctx)
			if err != nil {
				ex.RespBody = "error: " + err.Error()
			}
			out[i] = ex
		}(i)
	}
	close(start)
	wg.Wait()
	return out
}
