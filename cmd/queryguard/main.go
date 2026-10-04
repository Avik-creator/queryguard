// Command queryguard is a Postgres wire-protocol proxy that decides which
// tenants' queries run, and when, based on their estimated cost.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("queryguard", version)
		return
	}

	fmt.Fprintln(os.Stderr, "queryguard: the proxy is not implemented yet (milestone M1)")
	os.Exit(1)
}
