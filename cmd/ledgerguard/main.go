// ledgerguard runs ARTEX's money-invariant assurance probes against an
// authorized banking/payments API and writes JSON + HTML reports.
//
//	ledgerguard -target http://127.0.0.1:9900 -auth ENG-2026-014 -out ./lg-report
//	ledgerguard -profile bank.json -auth ENG-2026-014
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/ledgerguard"
)

func main() {
	target := flag.String("target", "http://127.0.0.1:9900", "base URL of the bundled bankrange (ignored with -profile)")
	profile := flag.String("profile", "", "JSON target profile for a real system")
	auth := flag.String("auth", "", "engagement authorization reference (required)")
	out := flag.String("out", "lg-report", "output path prefix (writes .json and .html)")
	only := flag.String("only", "", "comma-separated probe ids to run")
	flag.Parse()

	p := ledgerguard.RangeProfile(*target)
	if *profile != "" {
		b, err := os.ReadFile(*profile)
		if err != nil {
			die(err)
		}
		if err := json.Unmarshal(b, &p); err != nil {
			die(fmt.Errorf("profile: %w", err))
		}
	}
	var ids []string
	if *only != "" {
		ids = strings.Split(*only, ",")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := ledgerguard.Run(ctx, p, ledgerguard.Options{Authorization: *auth, Only: ids})
	if err != nil {
		die(err)
	}
	if dir := filepath.Dir(*out); dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	for ext, write := range map[string]func(*os.File) error{
		".json": func(f *os.File) error { return rep.WriteJSON(f) },
		".html": func(f *os.File) error { return rep.WriteHTML(f) },
	} {
		f, err := os.Create(*out + ext)
		if err != nil {
			die(err)
		}
		if err := write(f); err != nil {
			die(err)
		}
		f.Close()
	}
	fmt.Printf("LedgerGuard  %s  grade %s (%d/100)  findings %d  money-at-risk %s  requests %d\n",
		rep.Target, rep.Grade, rep.Score, len(rep.Findings), ledgerguard.Money(rep.ExposureINR, "INR"), rep.Requests)
	for _, r := range rep.Results {
		status := "PASS"
		detail := r.Note
		if r.Finding != nil {
			status = strings.ToUpper(r.Finding.Severity)
			detail = r.Finding.Exposure
		} else if r.Error != "" {
			status, detail = "ERROR", r.Error
		}
		fmt.Printf("  %-15s %-9s %s\n", r.Probe, status, detail)
	}
	fmt.Printf("reports: %s.json  %s.html\n", *out, *out)
	if len(rep.Findings) > 0 {
		os.Exit(2)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "ledgerguard:", err)
	os.Exit(1)
}
