// Package audit implements the typed, hash-chained security audit log
// (PRD §16.2, SC-20).
//
// Security events are typed messages accepted only from control-plane
// identities over IPC. Application stdout/stderr never reaches this log. Each
// event carries a monotonic sequence number and the SHA-256 hash of the
// previous event, so deletion, reordering or modification of any stored
// event is detectable by Verify. Signed checkpoints of the chain head are
// produced periodically and can be streamed off-host so evidence survives a
// node compromise.
package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Result values.
const (
	Success = "success"
	Denied  = "denied"
	Failure = "failure"
)

// Actor types.
const (
	ActorUser    = "user"
	ActorToken   = "api_token"
	ActorService = "service"
	ActorSystem  = "system"
	ActorGitHub  = "github"
	ActorAnon    = "anonymous"
)

// GenesisHash is the prev_hash of the first event.
var GenesisHash = strings.Repeat("0", 64)

// Event is one security audit record.
type Event struct {
	Seq          int64             `json:"seq"`
	Time         string            `json:"time"`
	Service      string            `json:"service"`
	ActorType    string            `json:"actor_type"`
	ActorID      string            `json:"actor_id"`
	SessionID    string            `json:"session_id,omitempty"`
	MFA          bool              `json:"mfa"`
	SourceIP     string            `json:"source_ip,omitempty"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	ProjectID    string            `json:"project_id,omitempty"`
	Result       string            `json:"result"`
	Details      map[string]string `json:"details,omitempty"`
	PrevHash     string            `json:"prev_hash"`
	Hash         string            `json:"hash"`
}

// Recognised detail keys (typed fields per PRD §16.2). Unknown keys are
// rejected so the audit schema stays reviewable.
var DetailKeys = map[string]bool{
	"delivery_id": true, "event": true, "commit": true, "ref": true, "artifact_digest": true, "deployment_id": true,
	"environment_id": true, "generation": true, "domain": true, "claim_id": true, "capability": true,
	"secret_name": true, "secret_scope": true, "secret_version": true, "update_version": true, "update_role": true,
	"target": true, "reason": true, "role": true, "user_id": true, "method": true, "trust_class": true, "runtime": true,
	"backup_id": true, "relay_instance": true, "session_target": true, "from": true, "to": true, "count": true,
	"error": true, "hostname": true, "installation_id": true, "repository": true, "policy": true, "token_id": true,
}

var actionRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,4}$`)

// Validate checks structural constraints of a caller-supplied event.
func (e *Event) Validate() error {
	if !actionRE.MatchString(e.Action) || len(e.Action) > 64 {
		return fmt.Errorf("invalid action %q", e.Action)
	}
	switch e.Result {
	case Success, Denied, Failure:
	default:
		return fmt.Errorf("invalid result %q", e.Result)
	}
	switch e.ActorType {
	case ActorUser, ActorToken, ActorService, ActorSystem, ActorGitHub, ActorAnon:
	default:
		return fmt.Errorf("invalid actor type %q", e.ActorType)
	}
	if len(e.Details) > 24 {
		return errors.New("too many details")
	}
	for k, v := range e.Details {
		if !DetailKeys[k] {
			return fmt.Errorf("unknown detail key %q", k)
		}
		if len(v) > 1024 {
			return fmt.Errorf("detail %q too long", k)
		}
	}
	for _, s := range []string{e.ActorID, e.SessionID, e.SourceIP, e.ResourceType, e.ResourceID, e.ProjectID} {
		if len(s) > 256 {
			return errors.New("field too long")
		}
	}
	return nil
}

// ComputeHash returns the chained hash of e (with e.Hash ignored).
func ComputeHash(e Event) string {
	e.Hash = ""
	b, _ := json.Marshal(e) // struct field order is fixed; map keys are sorted
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// VerifyChain checks a contiguous slice of events. prev is the hash of the
// event preceding events[0] (GenesisHash when events[0].Seq == 1). It returns
// the sequence number of the first broken link or 0 when intact.
func VerifyChain(prev string, events []Event) int64 {
	var lastSeq int64
	for i, e := range events {
		if i > 0 && e.Seq != lastSeq+1 {
			return e.Seq
		}
		if e.PrevHash != prev || ComputeHash(e) != e.Hash {
			return e.Seq
		}
		prev, lastSeq = e.Hash, e.Seq
	}
	return 0
}

// Checkpoint is a signed statement of the chain head.
type Checkpoint struct {
	Seq       int64  `json:"seq"`
	Hash      string `json:"hash"`
	Time      string `json:"time"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func checkpointMessage(c Checkpoint) []byte {
	return []byte(fmt.Sprintf("opendeploy-audit-checkpoint-v1\n%d\n%s\n%s\n%s", c.Seq, c.Hash, c.Time, c.KeyID))
}

// Sign signs a checkpoint.
func (c *Checkpoint) Sign(priv ed25519.PrivateKey) {
	c.Signature = hex.EncodeToString(ed25519.Sign(priv, checkpointMessage(*c)))
}

// VerifyCheckpoint checks a checkpoint signature.
func VerifyCheckpoint(c Checkpoint, pub ed25519.PublicKey) bool {
	sig, err := hex.DecodeString(c.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, checkpointMessage(c), sig)
}

// KeyID derives a short identifier for a public key.
func KeyID(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:8])
}

// Sink receives audit events from control-plane code.
type Sink interface {
	Append(ctx context.Context, e Event) (Event, error)
}

// Nop discards events (used only in unit tests of unrelated packages).
type Nop struct{}

func (Nop) Append(_ context.Context, e Event) (Event, error) { return e, nil }

// Memory records events in memory (tests).
type Memory struct {
	mu     sync.Mutex
	Events []Event
}

func (m *Memory) Append(_ context.Context, e Event) (Event, error) {
	if err := e.Validate(); err != nil {
		return e, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, e)
	return e, nil
}

// Find returns the recorded events with the given action.
func (m *Memory) Find(action string) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Event
	for _, e := range m.Events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}
