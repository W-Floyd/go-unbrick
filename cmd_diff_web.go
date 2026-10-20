package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/W-Floyd/go-unbrick/internal/infile"
	"github.com/W-Floyd/go-unbrick/pkg/analysis"
	"github.com/W-Floyd/go-unbrick/pkg/analysis/web"
)

// runDiffWeb serves the comparison as a web page, the same views as diff -i, until
// interrupted. The page shows the contents of the inputs, so it is for loopback
// unless the address says otherwise.
func runDiffWeb(cfg analysis.Config, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if host, _, _ := net.SplitHostPort(ln.Addr().String()); !net.ParseIP(host).IsLoopback() {
		fmt.Fprintln(os.Stderr, "warning: listening beyond this machine; anyone who can connect can read the inputs' contents")
	}
	run := analysis.Start(cfg)
	title := fmt.Sprintf("%s  vs  %s", infile.Base(cfg.A), infile.Base(cfg.B))
	srv := &http.Server{Handler: web.Handler(run, web.Options{Title: title})}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	fmt.Fprintf(os.Stderr, "serving http://%s/  (ctrl-c to stop)\n", ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
