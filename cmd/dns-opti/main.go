// Command dns-opti benchmarks public DNS resolvers and ranks them.
//
// It offers two interfaces: a visual CLI (progress panel plus ranked report)
// and a local loopback web page for analysing the results. All processing
// happens on the local machine; nothing is uploaded anywhere.
package main

import (
	"fmt"
	"os"
	"strings"

	"dns-opti/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// The commands already render their own output in the normal case, so
		// an error here is unexpected and worth a clear prefix.
		msg := err.Error()
		if !strings.HasPrefix(msg, "错误:") {
			msg = "错误: " + msg
		}
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
}
