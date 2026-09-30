package desktop

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Dialer opens a connection to the matching port inside the guest.
type Dialer func(ctx context.Context) (net.Conn, error)

// Forward accepts on ln and splices each connection to dial() until ctx is
// cancelled. It is how host loopback ports reach the VM guest over vsock.
func Forward(ctx context.Context, ln net.Listener, dial Dialer, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			up, err := dial(dctx)
			cancel()
			if err != nil {
				if log != nil {
					log.Debug("forward: guest dial failed", "addr", ln.Addr().String(), "err", err)
				}
				c.Close()
				return
			}
			Splice(c, up)
		}()
	}
}

type closeWriter interface{ CloseWrite() error }

// Splice copies both directions, propagating half-closes, and closes both
// connections when done.
func Splice(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
