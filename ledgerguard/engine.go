package ledgerguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Report is the full outcome of one assurance run.
type Report struct {
	Target        string        `json:"target"`
	BaseURL       string        `json:"base_url"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Authorization string        `json:"authorization"`
	Results       []ProbeResult `json:"results"`
	Findings      []Finding     `json:"findings"`
	Requests      int64         `json:"requests"`
	Budget        int           `json:"request_budget"`
	ExposureINR   int64         `json:"exposure_minor_inr"`
	Score         int           `json:"resilience_score"` // 0..100, higher is safer
	Grade         string        `json:"grade"`
}

// Options gate a run.
type Options struct {
	// Authorization is the engagement reference (ticket, SoW, RoE id). A run
	// without one is refused: LedgerGuard is an assurance tool, not a weapon.
	Authorization string
	// Only, if non-empty, restricts the run to these probe ids.
	Only []string
}

// Run executes every probe against the profile and returns the report.
func Run(ctx context.Context, p Profile, opt Options) (*Report, error) {
	if len(opt.Authorization) < 4 {
		return nil, errors.New("ledgerguard: refusing to run without an engagement authorization reference")
	}
	c, err := NewClient(p.BaseURL, p.Tokens, p.AllowHosts, p.Budget)
	if err != nil {
		return nil, err
	}
	r := &runner{p: p, c: c, oracle: &Oracle{c: c, identity: "auditor", path: p.PathRecon}}
	if _, err := r.oracle.Snapshot(ctx); err != nil {
		return nil, fmt.Errorf("ledgerguard: reconciliation oracle unreachable: %w", err)
	}
	rep := &Report{Target: p.Name, BaseURL: p.BaseURL, StartedAt: time.Now().UTC(), Authorization: opt.Authorization, Budget: p.Budget}
	want := map[string]bool{}
	for _, id := range opt.Only {
		want[id] = true
	}
	for _, pr := range probes {
		if len(want) > 0 && !want[pr.id] {
			continue
		}
		before := c.Used()
		res := pr.run(ctx, r)
		res.Requests = c.Used() - before
		if res.Finding != nil {
			f := res.Finding
			f.ID = fmt.Sprintf("%s-%03d", f.Probe, len(rep.Findings)+1)
			f.Controls = controlsFor(f.Invariant)
			rep.Findings = append(rep.Findings, *f)
			rep.ExposureINR += f.ExposureINR
		}
		rep.Results = append(rep.Results, res)
		if errors.Is(ctx.Err(), context.Canceled) {
			break
		}
	}
	rep.Requests = c.Used()
	rep.FinishedAt = time.Now().UTC()
	rep.Score, rep.Grade = score(rep)
	return rep, nil
}

var sevWeight = map[string]int{"critical": 30, "high": 15, "medium": 7, "low": 3}

func score(r *Report) (int, string) {
	s := 100
	for _, f := range r.Findings {
		s -= sevWeight[f.Severity]
	}
	if s < 0 {
		s = 0
	}
	switch {
	case s >= 90:
		return s, "A"
	case s >= 75:
		return s, "B"
	case s >= 50:
		return s, "C"
	case s >= 25:
		return s, "D"
	}
	return s, "F"
}

func jsonField(body, key string) string {
	var m map[string]any
	if json.Unmarshal([]byte(body), &m) != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
