package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/testcap"
)

// S3FromEnv returns the S3 backup configuration of a real test server
// started by tests/s3/minio.sh, or blocks the test when there is none.
func s3FromEnv(t *testing.T) config.BackupConfig {
	t.Helper()
	ep := os.Getenv("OPENDEPLOY_S3_ENDPOINT")
	if ep == "" {
		testcap.Blocked(t, "no S3 server (start one with: eval \"$(tests/s3/minio.sh)\")")
	}
	return config.BackupConfig{Endpoint: ep, Bucket: os.Getenv("OPENDEPLOY_S3_BUCKET"),
		AccessKey: os.Getenv("OPENDEPLOY_S3_ACCESS_KEY_FILE"), SecretKey: os.Getenv("OPENDEPLOY_S3_SECRET_KEY_FILE"),
		ObjectLock: true, RetainDays: 1}
}

func readKey(t *testing.T, env string) string {
	t.Helper()
	b, err := os.ReadFile(os.Getenv(env))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// raw sends a signed request with arbitrary credentials (the attacker's
// view of the bucket).
func raw(t *testing.T, method, endpoint, bucket, key string, q url.Values, ak, sk string, hdr http.Header) (int, http.Header, string) {
	t.Helper()
	u, _ := url.Parse(endpoint + "/" + bucket + "/" + key)
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(method, u.String(), nil)
	for k, v := range hdr {
		req.Header[k] = v
	}
	SignV4(req, ak, sk, "us-east-1", "s3", emptySHA256, time.Now())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(b)
}

// SC-21 against a real S3 implementation (MinIO) rather than the in-memory
// fake: write-once objects under compliance-mode object lock that neither
// the node's own credentials nor the storage administrator can delete
// before the retention date.
func TestS3TargetRealObjectLock(t *testing.T) {
	cfg := s3FromEnv(t)
	tgt, _, err := TargetFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	prefix := "locktest/" + hex.EncodeToString(rnd) + "/"
	key := prefix + "backup.enc"
	payload := bytes.Repeat([]byte("ciphertext-"), 100_000) // > 1 MiB
	retain := RetainUntil(cfg, time.Now())
	if err := tgt.Put(ctx, key, bytes.NewReader(payload), int64(len(payload)), retain); err != nil {
		t.Fatalf("put with object lock: %v", err)
	}
	rc, err := tgt.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip: %d bytes, want %d", len(got), len(payload))
	}
	keys, err := tgt.List(ctx, prefix)
	if err != nil || len(keys) != 1 || keys[0] != key {
		t.Fatalf("list %v %v", keys, err)
	}
	if _, err := tgt.Get(ctx, prefix+"missing"); err != ErrNotFound {
		t.Fatalf("missing object: %v", err)
	}
	if err := tgt.Put(ctx, key, strings.NewReader("overwrite"), 9, retain); err == nil {
		t.Fatal("existing backup object overwritten")
	}

	ep, bucket := cfg.Endpoint, cfg.Bucket
	nodeAK, nodeSK := readKey(t, "OPENDEPLOY_S3_ACCESS_KEY_FILE"), readKey(t, "OPENDEPLOY_S3_SECRET_KEY_FILE")
	code, h, body := raw(t, http.MethodHead, ep, bucket, key, nil, nodeAK, nodeSK, nil)
	version := h.Get("X-Amz-Version-Id")
	if code != 200 || version == "" || h.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" {
		t.Fatalf("head: %d version=%q lock=%q %s", code, version, h.Get("X-Amz-Object-Lock-Mode"), body)
	}
	// A compromised node cannot delete, with or without a version ID.
	for _, q := range []url.Values{nil, {"versionId": {version}}} {
		if code, _, body := raw(t, http.MethodDelete, ep, bucket, key, q, nodeAK, nodeSK, nil); code/100 == 2 {
			t.Fatalf("node credentials deleted a backup (%v): %d %s", q, code, body)
		}
	}
	// Nor can the storage administrator remove the locked version early,
	// even asking to bypass governance retention.
	rootAK, rootSK := readKey(t, "OPENDEPLOY_S3_ROOT_ACCESS_KEY_FILE"), readKey(t, "OPENDEPLOY_S3_ROOT_SECRET_KEY_FILE")
	bypass := http.Header{"X-Amz-Bypass-Governance-Retention": {"true"}}
	if code, _, body := raw(t, http.MethodDelete, ep, bucket, key, url.Values{"versionId": {version}}, rootAK, rootSK, bypass); code/100 == 2 {
		t.Fatalf("locked version deleted by the administrator: %d %s", code, body)
	}
	rc, err = tgt.Get(ctx, key)
	if err != nil {
		t.Fatalf("backup gone after delete attempts: %v", err)
	}
	rc.Close()
}
