// fakeshop is the demo origin keyfold's tests run against, plus a generator
// for matching access logs. see internal/fakeshop for what it does on
// purpose.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/fakeshop"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fakeshop serve [-addr :8080] | fakeshop logs [-n 200000] [-format nginx|caddy|cloudflare]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := fs.String("addr", "127.0.0.1:8080", "listen address")
		fs.Parse(os.Args[2:])
		log.Printf("fake shop on http://%s (send Host: %s)", *addr, fakeshop.Host)
		srv := &http.Server{Addr: *addr, Handler: fakeshop.New(), ReadHeaderTimeout: 10 * time.Second}
		log.Fatal(srv.ListenAndServe())
	case "logs":
		fs := flag.NewFlagSet("logs", flag.ExitOnError)
		n := fs.Int("n", 200000, "requests")
		format := fs.String("format", "nginx", "nginx, caddy or cloudflare")
		span := fs.Duration("span", 24*time.Hour, "time the requests are spread over")
		seed := fs.Uint64("seed", 42, "random seed, same seed same log")
		fs.Parse(os.Args[2:])
		err := fakeshop.WriteTraffic(os.Stdout, fakeshop.TrafficOptions{Requests: *n, Format: *format, Span: *span, Seed: *seed})
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "fakeshop: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
