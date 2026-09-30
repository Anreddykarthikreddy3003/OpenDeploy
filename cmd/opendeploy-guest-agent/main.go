// Command opendeploy-guest-agent runs inside the macOS VM guest and splices
// virtio-vsock connections from the host to the guest's loopback ports
// (dashboard/API and the Caddy edge). Only the hypervisor host (CID 2) may
// connect; the VM exposes no listening TCP port to the host network.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/desktop"
)

const hostCID = 2

// TokenPort serves the one-time owner bootstrap token to the host service
// (which shows it to the local administrator) until the owner exists.
const TokenPort = 1024

func main() {
	ports := flag.String("ports", "8080,80,443", "ports to forward (vsock port N -> 127.0.0.1:N)")
	tokenFile := flag.String("token-file", "/var/lib/opendeploy/platformd/bootstrap-token", "owner bootstrap token")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var wg sync.WaitGroup
	for _, p := range strings.Split(*ports, ",") {
		port, err := strconv.ParseUint(strings.TrimSpace(p), 10, 16)
		if err != nil || port == 0 {
			log.Error("invalid port", "port", p)
			os.Exit(2)
		}
		ln, err := vsock.Listen(uint32(port), nil)
		if err != nil {
			log.Error("vsock listen", "port", port, "err", err)
			os.Exit(1)
		}
		log.Info("forwarding", "vsock_port", port, "to", fmt.Sprintf("127.0.0.1:%d", port))
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := desktop.Forward(ctx, hostOnly{ln}, func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
			}, log)
			if err != nil {
				log.Error("forwarder stopped", "port", port, "err", err)
				cancel()
			}
		}()
	}
	tl, err := vsock.Listen(TokenPort, nil)
	if err != nil {
		log.Error("vsock listen", "port", TokenPort, "err", err)
		os.Exit(1)
	}
	go func() {
		<-ctx.Done()
		tl.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ln := hostOnly{tl}
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, err := os.ReadFile(*tokenFile)
			if err == nil {
				_, _ = c.Write([]byte(strings.TrimSpace(string(b))))
			}
			c.Close()
		}
	}()
	wg.Wait()
}

// hostOnly drops vsock connections that do not come from the host.
type hostOnly struct{ net.Listener }

func (l hostOnly) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return nil, err
		}
		if a, ok := c.RemoteAddr().(*vsock.Addr); ok && a.ContextID == hostCID {
			return c, nil
		}
		c.Close()
	}
}
