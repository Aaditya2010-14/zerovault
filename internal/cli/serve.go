package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

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

	httpSrv := &http.Server{Addr: *addr, Handler: handler}

	printSuccess("ZeroVault dashboard running at http://%s", *addr)
	printInfo("press Ctrl+C to stop")

	// Ctrl+C (os.Interrupt) triggers a graceful http.Server.Shutdown rather
	// than letting the OS kill the process mid-request: Shutdown stops
	// accepting new connections and waits (up to shutdownTimeout) for
	// in-flight requests — like a save mid-write — to finish cleanly.
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.ListenAndServe() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			printError("server error: %v", err)
			return 1
		}
		return 0
	case <-ctx.Done():
		stop()
		fmt.Println()
		printInfo("shutting down...")

		const shutdownTimeout = 5 * time.Second
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			printError("forced shutdown after %s: %v", shutdownTimeout, err)
			return 1
		}
		printSuccess("server stopped cleanly")
		return 0
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
