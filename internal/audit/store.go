package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func migrations() fs.FS {
	sub, _ := fs.Sub(migrationsFS, "migrations")
	return sub
}

// Store is the auditd-owned append-only chain.
type Store struct {
	db   *state.DB
	mu   sync.Mutex // serialises appends so seq/prev_hash are consistent
	priv ed25519.PrivateKey
	log  *slog.Logger
}

// OpenStore opens the audit DB. priv signs checkpoints.
func OpenStore(ctx context.Context, path string, priv ed25519.PrivateKey, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	db, err := state.Open(ctx, path, state.Options{Migrations: migrations(), Logger: log})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, priv: priv, log: log}
	if db.Degraded() == "" {
		if res, err := s.Verify(ctx); err != nil {
			return nil, err
		} else if !res.OK {
			db.EnterDegraded(fmt.Sprintf("audit chain broken at seq %d", res.BrokenAt))
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Degraded reports the degraded reason ("" when healthy).
func (s *Store) Degraded() string { return s.db.Degraded() }

// Append validates, chains and stores an event. service is the
// kernel-verified caller identity and overrides anything in e.
func (s *Store) Append(ctx context.Context, service string, e Event) (Event, error) {
	if err := e.Validate(); err != nil {
		return e, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var seq sql.NullInt64
		var prev sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		e.Seq = seq.Int64 + 1
		e.PrevHash = GenesisHash
		if prev.Valid {
			e.PrevHash = prev.String
		}
		e.Service = service
		e.Time = state.Now()
		e.Hash = ComputeHash(e)
		det, _ := json.Marshal(e.Details)
		if e.Details == nil {
			det = []byte("{}")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(seq,ts,service,actor_type,actor_id,session_id,mfa,source_ip,action,resource_type,
			resource_id,project_id,result,details,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			e.Seq, e.Time, e.Service, e.ActorType, e.ActorID, e.SessionID, e.MFA, e.SourceIP, e.Action, e.ResourceType,
			e.ResourceID, e.ProjectID, e.Result, string(det), e.PrevHash, e.Hash)
		return err
	})
	return e, err
}

func scanEvent(r interface{ Scan(...any) error }) (Event, error) {
	var e Event
	var det string
	err := r.Scan(&e.Seq, &e.Time, &e.Service, &e.ActorType, &e.ActorID, &e.SessionID, &e.MFA, &e.SourceIP, &e.Action,
		&e.ResourceType, &e.ResourceID, &e.ProjectID, &e.Result, &det, &e.PrevHash, &e.Hash)
	if err != nil {
		return e, err
	}
	if det != "{}" && det != "null" {
		_ = json.Unmarshal([]byte(det), &e.Details)
	}
	return e, nil
}

const eventCols = `seq,ts,service,actor_type,actor_id,session_id,mfa,source_ip,action,resource_type,resource_id,project_id,result,details,prev_hash,hash`

// Query filters events.
type Query struct {
	ProjectID    string `json:"project_id,omitempty"`
	ActionPrefix string `json:"action_prefix,omitempty"`
	ActorID      string `json:"actor_id,omitempty"`
	AfterSeq     int64  `json:"after_seq,omitempty"`
	BeforeSeq    int64  `json:"before_seq,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Descending   bool   `json:"descending,omitempty"`
}

func (s *Store) Query(ctx context.Context, q Query) ([]Event, error) {
	where := []string{"1=1"}
	var args []any
	if q.ProjectID != "" {
		where = append(where, "project_id=?")
		args = append(args, q.ProjectID)
	}
	if q.ActionPrefix != "" {
		where = append(where, "action LIKE ? ESCAPE '\\'")
		args = append(args, strings.NewReplacer("%", "\\%", "_", "\\_", "\\", "\\\\").Replace(q.ActionPrefix)+"%")
	}
	if q.ActorID != "" {
		where = append(where, "actor_id=?")
		args = append(args, q.ActorID)
	}
	if q.AfterSeq > 0 {
		where = append(where, "seq>?")
		args = append(args, q.AfterSeq)
	}
	if q.BeforeSeq > 0 {
		where = append(where, "seq<?")
		args = append(args, q.BeforeSeq)
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	order := "ASC"
	if q.Descending {
		order = "DESC"
	}
	args = append(args, q.Limit)
	rows, err := s.db.R().QueryContext(ctx, `SELECT `+eventCols+` FROM audit_events WHERE `+strings.Join(where, " AND ")+` ORDER BY seq `+order+` LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyResult summarises a chain verification.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Count    int64  `json:"count"`
	HeadSeq  int64  `json:"head_seq"`
	HeadHash string `json:"head_hash"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	// CheckpointsVerified counts signed checkpoints consistent with the chain.
	CheckpointsVerified int `json:"checkpoints_verified"`
	// CheckpointsForeign are chain-consistent checkpoints signed by a key
	// this node does not hold (previous node identity).
	CheckpointsForeign int `json:"checkpoints_foreign,omitempty"`
}

// Verify walks the full chain and all checkpoints.
func (s *Store) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{OK: true}
	prev := GenesisHash
	var lastSeq int64
	rows, err := s.db.R().QueryContext(ctx, `SELECT `+eventCols+` FROM audit_events ORDER BY seq`)
	if err != nil {
		return res, err
	}
	hashes := map[int64]string{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			rows.Close()
			return res, err
		}
		if e.Seq != lastSeq+1 || e.PrevHash != prev || ComputeHash(e) != e.Hash {
			res.OK, res.BrokenAt = false, e.Seq
			if e.Seq != lastSeq+1 {
				res.BrokenAt = lastSeq + 1
			}
			break
		}
		prev, lastSeq = e.Hash, e.Seq
		hashes[e.Seq] = e.Hash
		res.Count++
	}
	rows.Close()
	res.HeadSeq, res.HeadHash = lastSeq, prev
	if !res.OK {
		return res, nil
	}
	cps, err := s.Checkpoints(ctx, 0)
	if err != nil {
		return res, err
	}
	var pub ed25519.PublicKey
	if s.priv != nil {
		pub = s.priv.Public().(ed25519.PublicKey)
	}
	for _, c := range cps {
		h, ok := hashes[c.Seq]
		if !ok || h != c.Hash {
			// A checkpoint for an event that no longer exists means truncation.
			res.OK, res.BrokenAt = false, c.Seq
			return res, nil
		}
		if pub == nil || c.KeyID != KeyID(pub) {
			// Signed by another key (e.g. before a restore to a new node):
			// consistent with the chain, but not verifiable here.
			res.CheckpointsForeign++
			continue
		}
		if !VerifyCheckpoint(c, pub) {
			res.OK, res.BrokenAt = false, c.Seq
			return res, nil
		}
		res.CheckpointsVerified++
	}
	return res, nil
}

// Checkpoint records a signed checkpoint of the current head.
func (s *Store) Checkpoint(ctx context.Context) (*Checkpoint, error) {
	if s.priv == nil {
		return nil, errors.New("no checkpoint key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var c Checkpoint
	err := s.db.R().QueryRowContext(ctx, `SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&c.Seq, &c.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var exists int
	_ = s.db.R().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_checkpoints WHERE seq=?`, c.Seq).Scan(&exists)
	if exists > 0 {
		return nil, nil
	}
	c.Time = state.Now()
	c.KeyID = KeyID(s.priv.Public().(ed25519.PublicKey))
	c.Sign(s.priv)
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_checkpoints(seq,hash,ts,key_id,signature) VALUES(?,?,?,?,?)`, c.Seq, c.Hash, c.Time, c.KeyID, c.Signature)
		return err
	})
	return &c, err
}

func (s *Store) Checkpoints(ctx context.Context, afterSeq int64) ([]Checkpoint, error) {
	rows, err := s.db.R().QueryContext(ctx, `SELECT seq,hash,ts,key_id,signature FROM audit_checkpoints WHERE seq>? ORDER BY seq`, afterSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var c Checkpoint
		if err := rows.Scan(&c.Seq, &c.Hash, &c.Time, &c.KeyID, &c.Signature); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ForwarderConfig configures off-host streaming of the chain.
type ForwarderConfig struct {
	Name     string        // sink name (cursor key)
	URL      string        // HTTPS endpoint accepting NDJSON POSTs
	Token    string        // bearer token (write-only credential)
	Interval time.Duration // poll interval
	Client   *http.Client
}

// Forward streams events after the stored cursor to an off-host sink. The
// sink receives the full chained records so it can independently verify
// continuity; the local node cannot retract anything already forwarded.
func (s *Store) Forward(ctx context.Context, cfg ForwarderConfig) {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		if err := s.forwardOnce(ctx, cfg); err != nil {
			s.log.Warn("audit forward failed", "sink", cfg.Name, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Store) forwardOnce(ctx context.Context, cfg ForwarderConfig) error {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	var last int64
	_ = s.db.R().QueryRowContext(ctx, `SELECT last_seq FROM audit_forwarding WHERE sink=?`, cfg.Name).Scan(&last)
	for {
		evs, err := s.Query(ctx, Query{AfterSeq: last, Limit: 500})
		if err != nil {
			return err
		}
		if len(evs) == 0 {
			return nil
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, e := range evs {
			_ = enc.Encode(e)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, &buf)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		if cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
		}
		resp, err := cfg.Client.Do(req)
		if err != nil {
			s.recordForwardErr(ctx, cfg.Name, last, err)
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			err := fmt.Errorf("sink returned %d", resp.StatusCode)
			s.recordForwardErr(ctx, cfg.Name, last, err)
			return err
		}
		last = evs[len(evs)-1].Seq
		if err := s.db.Tx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO audit_forwarding(sink,last_seq,updated_at,last_error) VALUES(?,?,?, '')
				ON CONFLICT(sink) DO UPDATE SET last_seq=excluded.last_seq, updated_at=excluded.updated_at, last_error=''`, cfg.Name, last, state.Now())
			return err
		}); err != nil {
			return err
		}
	}
}

func (s *Store) recordForwardErr(ctx context.Context, name string, last int64, e error) {
	_ = s.db.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_forwarding(sink,last_seq,updated_at,last_error) VALUES(?,?,?,?)
			ON CONFLICT(sink) DO UPDATE SET updated_at=excluded.updated_at, last_error=excluded.last_error`, name, last, state.Now(), e.Error())
		return err
	})
}

// ForwardStatus reports forwarding cursors.
type ForwardStatus struct {
	Sink      string `json:"sink"`
	LastSeq   int64  `json:"last_seq"`
	UpdatedAt string `json:"updated_at"`
	LastError string `json:"last_error"`
}

func (s *Store) ForwardStatuses(ctx context.Context) ([]ForwardStatus, error) {
	rows, err := s.db.R().QueryContext(ctx, `SELECT sink,last_seq,updated_at,last_error FROM audit_forwarding ORDER BY sink`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ForwardStatus
	for rows.Next() {
		var f ForwardStatus
		if err := rows.Scan(&f.Sink, &f.LastSeq, &f.UpdatedAt, &f.LastError); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
