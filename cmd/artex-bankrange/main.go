// artex-bankrange serves the deliberately vulnerable core-banking practice range
// that LedgerGuard is demonstrated against. Keep it on loopback.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/bankrange"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9900", "listen address (keep it on loopback)")
	hardened := flag.Bool("hardened", false, "serve the fixed implementation of the same API")
	flag.Parse()
	mode := "VULNERABLE"
	if *hardened {
		mode = "hardened"
	}
	log.Printf("artex-bankrange (%s) listening on http://%s", mode, *addr)
	srv := &http.Server{Addr: *addr, Handler: bankrange.New(*hardened), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
