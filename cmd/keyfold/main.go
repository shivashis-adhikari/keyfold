// keyfold finds cache hits a cdn throws away because its cache key carries
// request parts that don't change the response.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// stamped by the linker at build time, see the makefile
var version = "dev"

const usage = `keyfold finds the cache hits your cdn throws away.

usage: keyfold <command> [flags] [args]

  routes   summarise route patterns and query params in access logs
  probe    re-request sampled urls on your origin, one change at a time
  synth    turn a probe report into a cache key plan
  sim      replay logs through cache policies with today's key and the plan's
  gen      write cloudflare, caddy or nginx config for a plan
  canary   record response hashes before a rollout, verify them after
  version  print the version

the usual order is routes, probe, synth, sim, gen, canary.
"keyfold <command> -h" shows the flags for one command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type command func(args []string, stdout, stderr io.Writer) error

var commands = map[string]command{
	"routes": cmdRoutes,
	"probe":  cmdProbe,
	"synth":  cmdSynth,
	"sim":    cmdSim,
	"gen":    cmdGen,
	"canary": cmdCanary,
}

// a non-zero exit that isn't an error worth printing, e.g. a canary that
// found mismatches and already said so.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(stdout, "keyfold", version)
		return 0
	}
	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "keyfold: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	err := cmd(args[1:], stdout, stderr)
	var code exitCode
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &code):
		return int(code)
	}
	fmt.Fprintf(stderr, "keyfold %s: %v\n", args[0], err)
	return 1
}

func newFlags(name, args string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: keyfold %s [flags] %s\n\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

// a flag that can be given more than once
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ", ") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }
