// Package bankrange is a deliberately vulnerable, in-memory core-banking API used
// as a practice range for LedgerGuard. It models the surface a card/ledger
// processor exposes (accounts, transfers, FX, OTP step-up) and ships with the
// classic money-losing bugs switched on. New(true) returns the
// fixed implementation of the same API, so a scan can be shown before/after.
//
// NEVER expose it to a network you do not control.
package bankrange

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type account struct {
	ID       string `json:"id"`
	Owner    string `json:"owner"`
	Currency string `json:"currency"`
	Balance  int64  `json:"balance_minor"` // paise for INR, cents for USD
}

type journalEntry struct {
	Seq       int64  `json:"seq"`
	TxnID     string `json:"txn_id"`
	Account   string `json:"account"`
	Amount    int64  `json:"amount_minor"` // signed
	Currency  string `json:"currency"`
	Reason    string `json:"reason"`
	Timestamp string `json:"ts"`
}

type otpChallenge struct {
	code     string
	attempts int
	locked   bool
}

type bank struct {
	hardened bool

	mu       sync.Mutex // guards maps; in vulnerable mode NOT held across check-then-act
	accounts map[string]*account
	tokens   map[string]string // bearer -> user
	journal  []journalEntry
	seq      int64
	idem     map[string]json.RawMessage
	otps     map[string]*otpChallenge
	txnSeq   int64

	// FX book: the bank's own treasury position per currency.
	treasury map[string]int64
}

const (
	usdInrRate = 8350 // 1 USD = 83.50 INR, expressed as paise per cent * 100
)

func newBank(hardened bool) *bank {
	b := &bank{
		hardened: hardened,
		accounts: map[string]*account{},
		tokens: map[string]string{
			"tok_alice":   "alice",
			"tok_bob":     "bob",
			"tok_mallory": "mallory",
			"tok_auditor": "auditor",
		},
		idem:     map[string]json.RawMessage{},
		otps:     map[string]*otpChallenge{},
		treasury: map[string]int64{"INR": 100_000_000_00, "USD": 1_000_000_00},
	}
	seed := []account{
		{"acc_alice_1", "alice", "INR", 2_500_000_00},
		{"acc_bob_1", "bob", "INR", 750_000_00},
		{"acc_mallory_1", "mallory", "INR", 1_000_00},
		{"acc_mallory_2", "mallory", "INR", 0},
		{"acc_mallory_usd", "mallory", "USD", 0},
	}
	for i := range seed {
		a := seed[i]
		b.accounts[a.ID] = &a
	}
	return b
}

func (b *bank) user(r *http.Request) string {
	h := r.Header.Get("Authorization")
	tok := strings.TrimPrefix(h, "Bearer ")
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens[tok]
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// post appends a journal line and moves the balance. Caller holds b.mu.
func (b *bank) post(txn, acc string, amt int64, ccy, reason string) {
	b.seq++
	b.journal = append(b.journal, journalEntry{
		Seq: b.seq, TxnID: txn, Account: acc, Amount: amt, Currency: ccy,
		Reason: reason, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if a, ok := b.accounts[acc]; ok {
		a.Balance += amt
	} else {
		b.treasury[ccy] += amt
	}
}

func (b *bank) nextTxn() string {
	b.txnSeq++
	return fmt.Sprintf("txn_%06d", b.txnSeq)
}

// GET /v1/accounts/{id}
func (b *bank) getAccount(w http.ResponseWriter, r *http.Request) {
	u := b.user(r)
	if u == "" {
		errJSON(w, 401, "unauthenticated")
		return
	}
	id := r.PathValue("id")
	b.mu.Lock()
	a, ok := b.accounts[id]
	var cp account
	if ok {
		cp = *a
	}
	b.mu.Unlock()
	if !ok {
		errJSON(w, 404, "not found")
		return
	}
	// VULN (BOLA / OWASP API1): vulnerable mode never checks ownership.
	if b.hardened && cp.Owner != u && u != "auditor" {
		errJSON(w, 404, "not found")
		return
	}
	writeJSON(w, 200, cp)
}

type transferReq struct {
	From           string `json:"from"`
	To             string `json:"to"`
	Amount         int64  `json:"amount_minor"`
	IdempotencyKey string `json:"idempotency_key"`
}

// POST /v1/transfers
func (b *bank) transfer(w http.ResponseWriter, r *http.Request) {
	u := b.user(r)
	if u == "" {
		errJSON(w, 401, "unauthenticated")
		return
	}
	var req transferReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		errJSON(w, 400, "bad json")
		return
	}
	if b.hardened {
		b.transferHardened(w, u, req)
		return
	}

	// VULN (idempotency check-then-set is not atomic): a duplicate submitted
	// while the first is in flight is executed again.
	if req.IdempotencyKey != "" {
		b.mu.Lock()
		prev, seen := b.idem[req.IdempotencyKey]
		b.mu.Unlock()
		if seen {
			w.Header().Set("Content-Type", "application/json")
			w.Write(prev)
			return
		}
	}

	b.mu.Lock()
	from, ok1 := b.accounts[req.From]
	to, ok2 := b.accounts[req.To]
	if !ok1 || !ok2 {
		b.mu.Unlock()
		errJSON(w, 404, "account not found")
		return
	}
	if from.Owner != u {
		b.mu.Unlock()
		errJSON(w, 403, "not your account")
		return
	}
	if from.Currency != to.Currency {
		b.mu.Unlock()
		errJSON(w, 400, "currency mismatch")
		return
	}
	// VULN (CWE-20): negative amounts are not rejected, so a "transfer" of
	// -X pulls money from the destination into the source.
	sufficient := from.Balance >= req.Amount
	b.mu.Unlock()
	if !sufficient {
		errJSON(w, 422, "insufficient funds")
		return
	}

	// VULN (CWE-362 TOCTOU): fraud/limits check happens here, outside the lock.
	time.Sleep(15 * time.Millisecond)

	b.mu.Lock()
	txn := b.nextTxn()
	b.post(txn, req.From, -req.Amount, from.Currency, "transfer out")
	b.post(txn, req.To, req.Amount, to.Currency, "transfer in")
	resp, _ := json.Marshal(map[string]any{"txn_id": txn, "status": "posted", "amount_minor": req.Amount})
	if req.IdempotencyKey != "" {
		b.idem[req.IdempotencyKey] = resp
	}
	b.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (b *bank) transferHardened(w http.ResponseWriter, u string, req transferReq) {
	if req.Amount <= 0 {
		errJSON(w, 400, "amount must be positive")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if req.IdempotencyKey != "" {
		key := u + "|" + req.IdempotencyKey
		if prev, seen := b.idem[key]; seen {
			w.Header().Set("Content-Type", "application/json")
			w.Write(prev)
			return
		}
	}
	from, ok1 := b.accounts[req.From]
	to, ok2 := b.accounts[req.To]
	if !ok1 || !ok2 {
		errJSON(w, 404, "account not found")
		return
	}
	if from.Owner != u {
		errJSON(w, 403, "not your account")
		return
	}
	if from.Currency != to.Currency {
		errJSON(w, 400, "currency mismatch")
		return
	}
	if from.Balance < req.Amount {
		errJSON(w, 422, "insufficient funds")
		return
	}
	txn := b.nextTxn()
	b.post(txn, req.From, -req.Amount, from.Currency, "transfer out")
	b.post(txn, req.To, req.Amount, to.Currency, "transfer in")
	resp, _ := json.Marshal(map[string]any{"txn_id": txn, "status": "posted", "amount_minor": req.Amount})
	if req.IdempotencyKey != "" {
		b.idem[u+"|"+req.IdempotencyKey] = resp
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

type fxReq struct {
	From   string `json:"from_account"`
	To     string `json:"to_account"`
	Amount int64  `json:"amount_minor"`
}

// POST /v1/fx/convert  INR <-> USD between two accounts of the same owner.
func (b *bank) fxConvert(w http.ResponseWriter, r *http.Request) {
	u := b.user(r)
	if u == "" {
		errJSON(w, 401, "unauthenticated")
		return
	}
	var req fxReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		errJSON(w, 400, "bad json")
		return
	}
	if req.Amount <= 0 {
		errJSON(w, 400, "amount must be positive")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	from, ok1 := b.accounts[req.From]
	to, ok2 := b.accounts[req.To]
	if !ok1 || !ok2 || from.Owner != u || to.Owner != u {
		errJSON(w, 404, "account not found")
		return
	}
	if from.Currency == to.Currency || from.Balance < req.Amount {
		errJSON(w, 422, "invalid conversion")
		return
	}
	var out int64
	switch {
	case from.Currency == "INR" && to.Currency == "USD":
		// paise -> cents: cents = paise / 83.50
		num := req.Amount * 100
		if b.hardened {
			out = num / usdInrRate // round down: bank never gives away a fraction
		} else {
			out = (num + usdInrRate - 1) / usdInrRate // VULN (CWE-682): ceil in customer's favour
		}
	case from.Currency == "USD" && to.Currency == "INR":
		num := req.Amount * usdInrRate
		if b.hardened {
			out = num / 100
		} else {
			out = (num + 99) / 100 // VULN: ceil again
		}
	default:
		errJSON(w, 400, "unsupported pair")
		return
	}
	if out <= 0 {
		errJSON(w, 422, "amount below minimum")
		return
	}
	txn := b.nextTxn()
	// Customer legs.
	b.post(txn, from.ID, -req.Amount, from.Currency, "fx sell")
	b.post(txn, to.ID, out, to.Currency, "fx buy")
	// Treasury legs: the bank takes the sold currency and pays the bought one.
	// In vulnerable mode the treasury leg is booked at the *fair* (unrounded)
	// value, so the rounding gift is created out of thin air: no GL absorbs it.
	if b.hardened {
		b.post(txn, "treasury", req.Amount, from.Currency, "fx treasury in")
		b.post(txn, "treasury", -out, to.Currency, "fx treasury out")
	} else {
		fair := out
		if from.Currency == "INR" {
			fair = req.Amount * 100 / usdInrRate
		} else {
			fair = req.Amount * usdInrRate / 100
		}
		b.post(txn, "treasury", req.Amount, from.Currency, "fx treasury in")
		b.post(txn, "treasury", -fair, to.Currency, "fx treasury out")
	}
	writeJSON(w, 200, map[string]any{"txn_id": txn, "credited_minor": out, "currency": to.Currency})
}

// POST /v1/otp/challenge  -> issues a 4-digit step-up OTP for high-value actions.
func (b *bank) otpChallenge(w http.ResponseWriter, r *http.Request) {
	u := b.user(r)
	if u == "" {
		errJSON(w, 401, "unauthenticated")
		return
	}
	b.mu.Lock()
	id := fmt.Sprintf("otp_%s_%d", u, time.Now().UnixNano())
	b.otps[id] = &otpChallenge{code: fmt.Sprintf("%04d", time.Now().UnixNano()%10000)}
	b.mu.Unlock()
	writeJSON(w, 200, map[string]string{"challenge_id": id, "delivery": "sms"})
}

// POST /v1/otp/verify {"challenge_id","otp"}
func (b *bank) otpVerify(w http.ResponseWriter, r *http.Request) {
	u := b.user(r)
	if u == "" {
		errJSON(w, 401, "unauthenticated")
		return
	}
	var req struct {
		ID  string `json:"challenge_id"`
		OTP string `json:"otp"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		errJSON(w, 400, "bad json")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.otps[req.ID]
	if !ok {
		errJSON(w, 404, "no such challenge")
		return
	}
	if c.locked {
		errJSON(w, 429, "challenge locked")
		return
	}
	c.attempts++
	if req.OTP == c.code {
		writeJSON(w, 200, map[string]string{"status": "verified"})
		return
	}
	// VULN (CWE-307): no attempt ceiling in vulnerable mode; 10^4 space is
	// brute-forceable in seconds.
	if b.hardened && c.attempts >= 5 {
		c.locked = true
		errJSON(w, 429, "challenge locked")
		return
	}
	errJSON(w, 401, "invalid otp")
}

// GET /v1/ledger/reconciliation  (auditor only): the read-only oracle feed.
// Real deployments map this to the bank's GL / recon export (CBS EOD files,
// a read replica, or a Kafka topic of journal postings).
func (b *bank) reconciliation(w http.ResponseWriter, r *http.Request) {
	if b.user(r) != "auditor" {
		errJSON(w, 403, "auditor only")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	totals := map[string]int64{}
	accs := make([]account, 0, len(b.accounts))
	for _, a := range b.accounts {
		totals[a.Currency] += a.Balance
		accs = append(accs, *a)
	}
	for c, v := range b.treasury {
		totals[c] += v
	}
	writeJSON(w, 200, map[string]any{
		"as_of":            time.Now().UTC().Format(time.RFC3339Nano),
		"accounts":         accs,
		"treasury":         b.treasury,
		"system_total":     totals,
		"journal_length":   len(b.journal),
		"journal_tail":     tail(b.journal, 50),
		"overdraft_policy": "none",
	})
}

func tail(j []journalEntry, n int) []journalEntry {
	if len(j) <= n {
		return append([]journalEntry(nil), j...)
	}
	return append([]journalEntry(nil), j[len(j)-n:]...)
}

func (b *bank) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/accounts/{id}", b.getAccount)
	mux.HandleFunc("POST /v1/transfers", b.transfer)
	mux.HandleFunc("POST /v1/fx/convert", b.fxConvert)
	mux.HandleFunc("POST /v1/otp/challenge", b.otpChallenge)
	mux.HandleFunc("POST /v1/otp/verify", b.otpVerify)
	mux.HandleFunc("GET /v1/ledger/reconciliation", b.reconciliation)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "hardened": b.hardened})
	})
	return mux
}

// New returns the range's HTTP handler. hardened selects the fixed implementation.
func New(hardened bool) http.Handler { return newBank(hardened).routes() }
