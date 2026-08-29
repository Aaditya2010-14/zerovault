package cli

import (
	"flag"
	"net"
	"net/http"

	"zerovault/internal/web"
)

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8787", "address to listen on (must be loopback — see threat model)")
	fs.Parse(args)

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		printError("invalid -addr %q: %v", *addr, err)
		return 1
	}
	if !isLoopbackHost(host) {
		printError("refusing to bind %q: the web dashboard is localhost-only by design (see README threat model)", *addr)
		return 1
	}

	wireAuditRunner()

	srv, err := web.NewServer(DefaultVaultPath())
	if err != nil {
		printError("failed to initialize web server: %v", err)
		return 1
	}
	handler, err := srv.Handler()
	if err != nil {
		printError("failed to build routes: %v", err)
		return 1
	}

	printSuccess("ZeroVault dashboard running at http://%s", *addr)
	printInfo("press Ctrl+C to stop")

	if err := http.ListenAndServe(*addr, handler); err != nil {
		printError("server error: %v", err)
		return 1
	}
	return 0
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
