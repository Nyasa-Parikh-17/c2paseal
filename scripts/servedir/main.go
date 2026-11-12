// Command servedir serves a directory over HTTP, for fixture scripts that
// need a local server (remote manifest stores). With a lifetime in seconds
// it exits on its own after that long, so a script that cannot kill it
// (as on Windows) is not left with a stray server.
//
// Usage: go run ./scripts/servedir <addr> <dir> [lifetime-seconds]
package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 3 && len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: servedir <addr> <dir> [lifetime-seconds]")
		os.Exit(2)
	}
	if len(os.Args) == 4 {
		secs, err := strconv.Atoi(os.Args[3])
		if err != nil || secs <= 0 {
			fmt.Fprintln(os.Stderr, "servedir: lifetime must be a positive number of seconds")
			os.Exit(2)
		}
		time.AfterFunc(time.Duration(secs)*time.Second, func() { os.Exit(0) })
	}
	if err := http.ListenAndServe(os.Args[1], http.FileServer(http.Dir(os.Args[2]))); err != nil {
		fmt.Fprintln(os.Stderr, "servedir:", err)
		os.Exit(1)
	}
}
