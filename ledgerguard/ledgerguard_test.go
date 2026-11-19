package ledgerguard_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/bankrange"
	"github.com/Autumn-27/artex/ledgerguard"
)

func run(t *testing.T, hardened bool) *ledgerguard.Report {
	t.Helper()
	srv := httptest.NewServer(bankrange.New(hardened))
	t.Cleanup(srv.Close)
	rep, err := ledgerguard.Run(context.Background(), ledgerguard.RangeProfile(srv.URL), ledgerguard.Options{Authorization: "TEST-RANGE"})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestVulnerableRangeBreaksEveryInvariant(t *testing.T) {
	rep := run(t, false)
	got := map[string]bool{}
	for _, f := range rep.Findings {
		got[f.Probe] = true
		if len(f.Evidence) == 0 || len(f.Controls) == 0 {
			t.Errorf("%s: finding without evidence or controls", f.ID)
		}
	}
	for _, id := range []string{"LG-AUTHZ-READ", "LG-STEPUP", "LG-SIGN", "LG-ROUNDING", "LG-IDEMPOTENCY", "LG-DOUBLESPEND"} {
		if !got[id] {
			t.Errorf("expected finding from %s; results: %+v", id, rep.Results)
		}
	}
	if rep.Grade != "F" || rep.ExposureINR <= 0 {
		t.Errorf("grade %s exposure %d", rep.Grade, rep.ExposureINR)
	}
	var html bytes.Buffer
	if err := rep.WriteHTML(&html); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), "PCI DSS v4.0") {
		t.Error("html report missing control matrix")
	}
}

func TestHardenedRangePasses(t *testing.T) {
	rep := run(t, true)
	for _, r := range rep.Results {
		if r.Error != "" {
			t.Errorf("%s errored: %s", r.Probe, r.Error)
		}
	}
	if len(rep.Findings) != 0 {
		for _, f := range rep.Findings {
			t.Errorf("unexpected finding on hardened range: %s %s", f.ID, f.Summary)
		}
	}
	if rep.Grade != "A" {
		t.Errorf("grade %s", rep.Grade)
	}
}

func TestRefusesOutOfScopeAndUnauthorized(t *testing.T) {
	p := ledgerguard.RangeProfile("http://bank.example.com")
	if _, err := ledgerguard.Run(context.Background(), p, ledgerguard.Options{Authorization: "ENG-1"}); err == nil {
		t.Error("out-of-scope host accepted")
	}
	p = ledgerguard.RangeProfile("http://127.0.0.1:1")
	if _, err := ledgerguard.Run(context.Background(), p, ledgerguard.Options{}); err == nil {
		t.Error("run without authorization accepted")
	}
}

func TestMoney(t *testing.T) {
	for in, want := range map[int64]string{
		418503750: "₹41,85,037.50", 100: "₹1.00", -5036_50: "-₹5,036.50", 12345678901: "₹12,34,56,789.01",
	} {
		if got := ledgerguard.Money(in, "INR"); got != want {
			t.Errorf("Money(%d)=%s want %s", in, got, want)
		}
	}
	if got := ledgerguard.Money(123456789, "USD"); got != "$1,234,567.89" {
		t.Errorf("usd %s", got)
	}
}
