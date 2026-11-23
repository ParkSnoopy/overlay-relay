package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	status := runHubCLI(ctx, os.Args[1:], os.LookupEnv, os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(status)
}

func runHubCLI(ctx context.Context, args []string, lookupEnv func(string) (string, bool), stdin io.Reader, stdout, stderr io.Writer) int {
	options, response := parseHubCLI(args, lookupEnv)
	if response != nil {
		writer := stdout
		if response.status != 0 {
			writer = stderr
		}
		if _, err := io.WriteString(writer, response.text); err != nil {
			return 1
		}
		return response.status
	}

	var err error
	if options.command != "" {
		err = runHubAdmin(&options, stdin, stdout)
	} else {
		var listener net.Listener
		listener, err = net.Listen("tcp", options.listen)
		if err == nil {
			hosts := allowedHosts(options.hosts)
			_, _ = fmt.Fprintf(stderr, "overlay hub listening hosts=%d\n", len(hosts))
			err = serveHub(ctx, listener, options.directory, hosts, options.space, options.peerSocket)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "overlay hub stopped error=%v\n", err)
		return 1
	}
	return 0
}

func allowedHosts(raw string) []string {
	hosts := []string{}
	for host := range strings.SplitSeq(raw, ",") {
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}
