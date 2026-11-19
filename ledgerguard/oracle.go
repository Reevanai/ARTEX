package ledgerguard

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Snapshot is the oracle's view of the ledger at one instant.
type Snapshot struct {
	Accounts    map[string]AccountView `json:"accounts"`
	SystemTotal map[string]int64       `json:"system_total"`
	JournalLen  int                    `json:"journal_length"`
	Journal     []JournalLine          `json:"journal_tail"`
}

// AccountView is one account as the reconciliation feed reports it.
type AccountView struct {
	ID       string `json:"id"`
	Owner    string `json:"owner"`
	Currency string `json:"currency"`
	Balance  int64  `json:"balance_minor"`
}

// JournalLine is one posting from the feed.
type JournalLine struct {
	TxnID   string `json:"txn_id"`
	Account string `json:"account"`
	Amount  int64  `json:"amount_minor"`
}

// Oracle reads the target's read-only reconciliation feed. In production this
// adapter points at a GL export, CBS end-of-day file, a read replica or a
// journal topic; LedgerGuard never needs write access to judge an invariant.
type Oracle struct {
	c        *Client
	identity string
	path     string
}

// Snapshot fetches the current ledger state.
func (o *Oracle) Snapshot(ctx context.Context) (Snapshot, error) {
	var raw struct {
		Accounts    []AccountView    `json:"accounts"`
		SystemTotal map[string]int64 `json:"system_total"`
		JournalLen  int              `json:"journal_length"`
		Journal     []JournalLine    `json:"journal_tail"`
	}
	ex, err := o.c.Do(ctx, o.identity, "GET", o.path, nil, &raw)
	if err != nil {
		return Snapshot{}, err
	}
	if ex.Status != 200 {
		return Snapshot{}, fmt.Errorf("oracle returned %d: %s", ex.Status, ex.RespBody)
	}
	s := Snapshot{Accounts: map[string]AccountView{}, SystemTotal: raw.SystemTotal, JournalLen: raw.JournalLen, Journal: raw.Journal}
	for _, a := range raw.Accounts {
		s.Accounts[a.ID] = a
	}
	return s, nil
}

// Violation is one broken invariant between two snapshots.
type Violation struct {
	Invariant string `json:"invariant"`
	Detail    string `json:"detail"`
	Currency  string `json:"currency,omitempty"`
	Delta     int64  `json:"delta_minor,omitempty"`
}

// Invariant names. These are the contract a ledger must keep regardless of
// what any API caller does.
const (
	InvConservation = "conservation"    // internal movements never change the system total
	InvNonNegative  = "non_negative"    // no account below zero without an overdraft line
	InvDoubleEntry  = "double_entry"    // each txn's postings net to zero per currency
	InvAuthority    = "authority"       // only the owner can move or read an account
	InvIdempotency  = "idempotency"     // one idempotency key, at most one posting set
	InvStepUpCeil   = "step_up_ceiling" // step-up auth locks after a bounded number of failures
)

// CheckLedger compares before/after for the structural invariants.
func CheckLedger(before, after Snapshot) []Violation {
	var vs []Violation
	ccys := map[string]bool{}
	for c := range before.SystemTotal {
		ccys[c] = true
	}
	for c := range after.SystemTotal {
		ccys[c] = true
	}
	keys := make([]string, 0, len(ccys))
	for c := range ccys {
		keys = append(keys, c)
	}
	sort.Strings(keys)
	for _, c := range keys {
		if d := after.SystemTotal[c] - before.SystemTotal[c]; d != 0 {
			vs = append(vs, Violation{InvConservation,
				fmt.Sprintf("system total for %s moved by %s with no external inflow", c, Money(d, c)), c, d})
		}
	}
	ids := make([]string, 0, len(after.Accounts))
	for id := range after.Accounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := after.Accounts[id]
		if a.Balance < 0 {
			vs = append(vs, Violation{InvNonNegative,
				fmt.Sprintf("account %s is overdrawn at %s with no overdraft facility", id, Money(a.Balance, a.Currency)), a.Currency, a.Balance})
		}
	}
	return vs
}

// Money renders minor units as a human amount.
func Money(minor int64, ccy string) string {
	sign := ""
	if minor < 0 {
		sign = "-"
		minor = -minor
	}
	sym := ccy + " "
	switch ccy {
	case "INR":
		sym = "₹"
	case "USD":
		sym = "$"
	}
	whole := fmt.Sprint(minor / 100)
	if ccy == "INR" {
		whole = groupIndian(whole)
	} else {
		whole = groupWestern(whole)
	}
	return fmt.Sprintf("%s%s%s.%02d", sign, sym, whole, minor%100)
}

// groupIndian applies lakh/crore grouping: 12,34,56,789.
func groupIndian(s string) string {
	if len(s) <= 3 {
		return s
	}
	head, tail := s[:len(s)-3], s[len(s)-3:]
	var parts []string
	for len(head) > 2 {
		parts = append([]string{head[len(head)-2:]}, parts...)
		head = head[:len(head)-2]
	}
	if head != "" {
		parts = append([]string{head}, parts...)
	}
	return strings.Join(parts, ",") + "," + tail
}

func groupWestern(s string) string {
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
