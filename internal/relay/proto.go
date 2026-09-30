package relay

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
)

// ALPN protocols on the tunnel endpoint.
const (
	ALPNEnroll = "odr-enroll/1"
	ALPNTunnel = "odr-tunnel/1"
)

// Control message types (newline-delimited JSON on the agent's first
// stream).
const (
	MsgRoutes    = "routes"     // agent -> server: full desired host list
	MsgRoutesAck = "routes_ack" // server -> agent
	MsgRenew     = "renew"      // agent -> server: CSR for credential rotation
	MsgRenewed   = "renewed"    // server -> agent
	MsgError     = "error"
)

// ControlMsg is one control-plane message.
type ControlMsg struct {
	Type     string            `json:"type"`
	Hosts    []string          `json:"hosts,omitempty"`
	Accepted []string          `json:"accepted,omitempty"`
	Rejected map[string]string `json:"rejected,omitempty"`
	CSR      string            `json:"csr,omitempty"`
	Cert     string            `json:"cert,omitempty"`
	Message  string            `json:"message,omitempty"`
}

// StreamHeader precedes the raw bytes of every forwarded connection. It
// carries only routing metadata; the backend is chosen by the relay from
// the authenticated route table, never by the public client.
type StreamHeader struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"` // tls | http
	Host   string `json:"host"`
	Client string `json:"client"`
}

// EnrollRequest / EnrollResponse are the enrollment API bodies.
type EnrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

type EnrollResponse struct {
	Tenant   string `json:"tenant"`
	Instance string `json:"instance"`
	Cert     string `json:"cert"`
	CA       string `json:"ca"`
}

const maxLine = 64 << 10

// lineReader reads bounded JSON lines.
type lineReader struct{ r *bufio.Reader }

func newLineReader(r io.Reader) *lineReader { return &lineReader{bufio.NewReaderSize(r, 4096)} }

func (l *lineReader) next(v any) error {
	var buf []byte
	for {
		chunk, isPrefix, err := l.r.ReadLine()
		if err != nil {
			return err
		}
		buf = append(buf, chunk...)
		if len(buf) > maxLine {
			return errors.New("control line too long")
		}
		if !isPrefix {
			break
		}
	}
	return json.Unmarshal(buf, v)
}

func writeLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
