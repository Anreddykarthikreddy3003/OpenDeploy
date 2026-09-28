package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func seal(t *testing.T, plain []byte, id string) ([]byte, []byte, []byte) {
	dek, prefix := NewDEK(), []byte{1, 2, 3, 4}
	var buf bytes.Buffer
	e, err := NewEncryptor(&buf, dek, id, prefix)
	if err != nil {
		t.Fatal(err)
	}
	// Write in odd-sized pieces.
	for p := plain; len(p) > 0; {
		n := min(len(p), 77777)
		if _, err := e.Write(p[:n]); err != nil {
			t.Fatal(err)
		}
		p = p[n:]
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), dek, prefix
}

func open(ct, dek, prefix []byte, id string) ([]byte, error) {
	d, err := NewDecryptor(bytes.NewReader(ct), dek, id, prefix)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(d)
}

func TestStreamRoundTripAndTamper(t *testing.T) {
	overhead := 16
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 5} {
		plain := make([]byte, size)
		_, _ = rand.Read(plain)
		ct, dek, prefix := seal(t, plain, "bkp_x")
		got, err := open(ct, dek, prefix, "bkp_x")
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: %v", size, err)
		}
		if size < 2*ChunkSize {
			continue
		}
		full := ChunkSize + overhead
		// Truncation at a chunk boundary.
		if _, err := open(ct[:2*full], dek, prefix, "bkp_x"); !errors.Is(err, ErrTampered) {
			t.Fatalf("truncation accepted: %v", err)
		}
		// Swapping two chunks.
		sw := append([]byte{}, ct...)
		copy(sw[:full], ct[full:2*full])
		copy(sw[full:2*full], ct[:full])
		if _, err := open(sw, dek, prefix, "bkp_x"); !errors.Is(err, ErrTampered) {
			t.Fatalf("reorder accepted: %v", err)
		}
		// Bit flip.
		fl := append([]byte{}, ct...)
		fl[len(fl)/2] ^= 1
		if _, err := open(fl, dek, prefix, "bkp_x"); !errors.Is(err, ErrTampered) {
			t.Fatalf("bit flip accepted: %v", err)
		}
		// Ciphertext moved to another backup id.
		if _, err := open(ct, dek, prefix, "bkp_y"); !errors.Is(err, ErrTampered) {
			t.Fatalf("cross-backup splice accepted: %v", err)
		}
	}
}

func files(t *testing.T, dir string, m map[string]string) []Source {
	var out []Source
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := filepath.Join(dir, strings.ReplaceAll(n, "/", "_"))
		if err := os.WriteFile(p, []byte(m[n]), 0o600); err != nil {
			t.Fatal(err)
		}
		out = append(out, Source{Component: Component{Name: n, Kind: "test"}, Path: p})
	}
	return out
}

func TestBackupRestore(t *testing.T) {
	ctx := context.Background()
	stage := t.TempDir()
	tgt := &LocalTarget{Dir: t.TempDir()}
	var master MasterKey
	_, _ = rand.Read(master[:])
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	secret := "PLAINTEXT-CANARY-" + strings.Repeat("z", 64)
	big := strings.Repeat("0123456789", 300_000)
	srcs := files(t, stage, map[string]string{"platform/platform.db": "db " + secret, "volumes/v1.tar": big, "config/node.yaml": "profile: standard\n"})
	m, err := Create(ctx, Options{Node: "n1", Version: "2.0.0", Sources: srcs, Target: tgt, Prefix: "od/", Master: master, Signer: signer, StageDir: stage})
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := List(ctx, tgt, "od/")
	if len(ids) != 1 || ids[0] != m.ID {
		t.Fatalf("list %v", ids)
	}
	// ST-11: no plaintext at rest.
	_ = filepath.Walk(tgt.Dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte("PLAINTEXT-CANARY")) || bytes.Contains(b, []byte("0123456789012345")) {
				t.Fatalf("plaintext found in %s", p)
			}
		}
		return nil
	})
	out := t.TempDir()
	dest := func(c Component) (string, error) { return filepath.Join(out, c.Name), nil }
	pub := signer.Public().(ed25519.PublicKey)
	if _, err := Restore(ctx, tgt, "od/", m.ID, master, pub, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "platform/platform.db")); string(b) != "db "+secret {
		t.Fatalf("restored %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "volumes/v1.tar")); string(b) != big {
		t.Fatal("large component mismatch")
	}
	// Wrong master key.
	var other MasterKey
	_, _ = rand.Read(other[:])
	if _, err := Restore(ctx, tgt, "od/", m.ID, other, pub, dest); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("wrong key: %v", err)
	}
	// Pinned signer mismatch.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Restore(ctx, tgt, "od/", m.ID, master, otherPub, dest); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("pinned signer: %v", err)
	}
	// Forged manifest (edited sizes) fails signature verification.
	mp := filepath.Join(tgt.Dir, "od", m.ID, "manifest.json")
	orig, _ := os.ReadFile(mp)
	_ = os.Chmod(mp, 0o600)
	forged := bytes.Replace(orig, []byte(`"node":"n1"`), []byte(`"node":"n2"`), 1)
	if bytes.Equal(forged, orig) {
		t.Fatal("test did not modify the manifest")
	}
	_ = os.WriteFile(mp, forged, 0o600)
	if _, err := Restore(ctx, tgt, "od/", m.ID, master, nil, dest); err == nil {
		t.Fatal("forged manifest accepted")
	}
	_ = os.WriteFile(mp, orig, 0o600)
	// Corrupted data object.
	dp := filepath.Join(tgt.Dir, "od", m.ID, "data.enc")
	_ = os.Chmod(dp, 0o600)
	d, _ := os.ReadFile(dp)
	d[len(d)-40] ^= 0xff
	_ = os.WriteFile(dp, d, 0o600)
	out2 := t.TempDir()
	if _, err := Restore(ctx, tgt, "od/", m.ID, master, pub, func(c Component) (string, error) { return filepath.Join(out2, c.Name), nil }); err == nil {
		t.Fatal("corrupted backup restored")
	}
	if _, err := os.Stat(filepath.Join(out2, "config/node.yaml")); err == nil {
		t.Fatal("partial restore left final files behind")
	}
	// Objects are immutable.
	if err := tgt.Put(ctx, "od/"+m.ID+"/manifest.json", strings.NewReader("x"), 1, nil); err == nil {
		t.Fatal("overwrite allowed")
	}
}

// AWS S3 documentation example (ListObjects, SigV4).
func TestSigV4Vector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
	SignV4(req, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "s3", emptySHA256,
		time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("signature\n got %s\nwant %s", got, want)
	}
}

// fakeS3 is an in-memory S3 with object-lock semantics: locked objects can
// never be deleted or overwritten, and DELETE is recorded (and refused).
type fakeS3 struct {
	mu      sync.Mutex
	objs    map[string][]byte
	locks   map[string]string
	methods []string
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, r.Method)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AK/") {
		http.Error(w, "unsigned", 403)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	switch r.Method {
	case "PUT":
		if _, ok := f.objs[key]; ok && r.Header.Get("If-None-Match") == "*" {
			http.Error(w, "exists", 412)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.objs[key] = b
		f.locks[key] = r.Header.Get("X-Amz-Object-Lock-Mode") + "|" + r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")
	case "GET":
		if r.URL.Query().Get("list-type") == "2" {
			type c struct {
				Key string `xml:"Key"`
			}
			var res struct {
				XMLName  xml.Name `xml:"ListBucketResult"`
				Contents []c      `xml:"Contents"`
			}
			for k := range f.objs {
				if strings.HasPrefix(k, r.URL.Query().Get("prefix")) {
					res.Contents = append(res.Contents, c{k})
				}
			}
			_ = xml.NewEncoder(w).Encode(res)
			return
		}
		b, ok := f.objs[key]
		if !ok {
			http.Error(w, "nope", 404)
			return
		}
		_, _ = w.Write(b)
	default:
		http.Error(w, "forbidden by object lock / credentials", 403)
	}
}

func TestS3TargetObjectLock(t *testing.T) {
	ctx := context.Background()
	fs := &fakeS3{objs: map[string][]byte{}, locks: map[string]string{}}
	srv := httptest.NewServer(fs)
	defer srv.Close()
	tgt := &S3Target{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket", AccessKey: "AK", SecretKey: "SK", ObjectLock: "COMPLIANCE"}
	var master MasterKey
	_, _ = rand.Read(master[:])
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	stage := t.TempDir()
	until := time.Now().Add(30 * 24 * time.Hour)
	m, err := Create(ctx, Options{Sources: files(t, stage, map[string]string{"a": "alpha"}), Target: tgt, Prefix: "p/", Master: master, Signer: signer,
		StageDir: stage, RetainUntil: &until, ObjectLock: true})
	if err != nil {
		t.Fatal(err)
	}
	for k, l := range fs.locks {
		if !strings.HasPrefix(l, "COMPLIANCE|") || len(l) < 20 {
			t.Fatalf("%s uploaded without object lock: %q", k, l)
		}
	}
	if ids, _ := List(ctx, tgt, "p/"); len(ids) != 1 || ids[0] != m.ID {
		t.Fatalf("list %v", ids)
	}
	out := t.TempDir()
	if _, err := Restore(ctx, tgt, "p/", m.ID, master, nil, func(c Component) (string, error) { return filepath.Join(out, c.Name), nil }); err != nil {
		t.Fatal(err)
	}
	// Re-running the same backup id cannot overwrite existing objects.
	if err := tgt.Put(ctx, "p/"+m.ID+"/manifest.json", strings.NewReader("x"), 1, nil); err == nil {
		t.Fatal("overwrite allowed")
	}
	for _, meth := range fs.methods {
		if meth == "DELETE" {
			t.Fatal("backup client issued a DELETE")
		}
	}
}
