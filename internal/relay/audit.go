package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditRecord is one relay security event (enrollment, tunnel auth, route
// authorisation, revocation). Records are hash-chained so truncation or
// edits of the local file are detectable; operators should ship the file
// off-host like the node audit chain.
type AuditRecord struct {
	Time     string `json:"time"`
	Action   string `json:"action"`
	Tenant   string `json:"tenant,omitempty"`
	Instance string `json:"instance,omitempty"`
	Host     string `json:"host,omitempty"`
	Source   string `json:"source,omitempty"`
	Result   string `json:"result"`
	Reason   string `json:"reason,omitempty"`
	Prev     string `json:"prev"`
	Hash     string `json:"hash"`
}

// Auditor appends chained records to a file (and keeps them in memory
// for tests when Path is empty).
type Auditor struct {
	mu      sync.Mutex
	f       *os.File
	prev    string
	Records []AuditRecord
}

// OpenAuditor opens (appending) the audit log at path; "" keeps records in
// memory only.
func OpenAuditor(path string) (*Auditor, error) {
	a := &Auditor{prev: "genesis"}
	if path == "" {
		return a, nil
	}
	if b, err := os.ReadFile(path); err == nil {
		// Resume the chain from the last record.
		for i := len(b) - 2; i >= -1; i-- {
			if i == -1 || b[i] == '\n' {
				var r AuditRecord
				if json.Unmarshal(b[i+1:], &r) == nil && r.Hash != "" {
					a.prev = r.Hash
				}
				break
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	a.f = f
	return a, nil
}

// Log appends a record.
func (a *Auditor) Log(r AuditRecord) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r.Time = time.Now().UTC().Format(time.RFC3339Nano)
	r.Prev, r.Hash = a.prev, ""
	b, _ := json.Marshal(r)
	h := sha256.Sum256(append([]byte(a.prev), b...))
	r.Hash = hex.EncodeToString(h[:])
	a.prev = r.Hash
	if a.f != nil {
		line, _ := json.Marshal(r)
		_, _ = a.f.Write(append(line, '\n'))
	} else {
		a.Records = append(a.Records, r)
	}
}

// Find returns in-memory records matching action and result.
func (a *Auditor) Find(action, result string) []AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditRecord
	for _, r := range a.Records {
		if r.Action == action && (result == "" || r.Result == result) {
			out = append(out, r)
		}
	}
	return out
}

// Close closes the file.
func (a *Auditor) Close() error {
	if a == nil || a.f == nil {
		return nil
	}
	return a.f.Close()
}
