package backup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Target stores backup objects. Implementations never delete: retention is
// enforced by the storage (object lock / lifecycle rules) so a compromised
// node cannot erase its own history.
type Target interface {
	Put(ctx context.Context, key string, r io.Reader, size int64, retainUntil *time.Time) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	List(ctx context.Context, prefix string) ([]string, error)
	String() string
}

// ErrNotFound is returned for missing objects.
var ErrNotFound = errors.New("backup object not found")

// LocalTarget writes to a directory (a mounted disk or NAS). Objects are
// written once and made read-only.
type LocalTarget struct{ Dir string }

func (t *LocalTarget) String() string { return "file://" + t.Dir }

func (t *LocalTarget) path(key string) (string, error) {
	clean := path.Clean("/" + key)
	if clean == "/" || strings.Contains(key, "..") {
		return "", fmt.Errorf("invalid key %q", key)
	}
	return filepath.Join(t.Dir, filepath.FromSlash(clean)), nil
}

func (t *LocalTarget) Put(_ context.Context, key string, r io.Reader, _ int64, _ *time.Time) error {
	p, err := t.path(key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("backup object %s already exists (objects are immutable)", key)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func (t *LocalTarget) Get(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := t.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}

func (t *LocalTarget) List(_ context.Context, prefix string) ([]string, error) {
	var out []string
	err := filepath.Walk(t.Dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if fi.IsDir() || strings.HasPrefix(fi.Name(), ".put-") {
			return nil
		}
		rel, _ := filepath.Rel(t.Dir, p)
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// S3Target talks to any S3-compatible store with AWS Signature V4. Use
// credentials that can PutObject/GetObject/ListBucket but not delete, and a
// bucket with versioning + object lock; the node then cannot destroy
// protected copies even if fully compromised (SC-21).
type S3Target struct {
	Endpoint   string // https://s3.eu-west-1.amazonaws.com or https://minio.local:9000
	Region     string
	Bucket     string
	AccessKey  string
	SecretKey  string
	ObjectLock string // "" | GOVERNANCE | COMPLIANCE
	HC         *http.Client
	now        func() time.Time
}

func (t *S3Target) String() string { return "s3://" + t.Bucket + " (" + t.Endpoint + ")" }

func (t *S3Target) client() *http.Client {
	if t.HC != nil {
		return t.HC
	}
	return &http.Client{Timeout: 30 * time.Minute}
}

func (t *S3Target) objectURL(key string, q url.Values) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSuffix(t.Endpoint, "/"))
	if err != nil {
		return nil, err
	}
	u.Path = "/" + t.Bucket
	if key != "" {
		u.Path += "/" + key
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func (t *S3Target) do(ctx context.Context, method string, u *url.URL, body io.Reader, size int64, payloadHash string, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if size >= 0 && body != nil {
		req.ContentLength = size
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	now := time.Now
	if t.now != nil {
		now = t.now
	}
	SignV4(req, t.AccessKey, t.SecretKey, t.Region, "s3", payloadHash, now())
	res, err := t.client().Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		return nil, ErrNotFound
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return nil, fmt.Errorf("s3 %s %s: %s %s", method, u.Path, res.Status, strings.TrimSpace(string(b)))
	}
	return res, nil
}

func (t *S3Target) Put(ctx context.Context, key string, r io.Reader, size int64, retainUntil *time.Time) error {
	u, err := t.objectURL(key, nil)
	if err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/octet-stream")
	// Refuse to overwrite an existing object (S3 conditional write).
	hdr.Set("If-None-Match", "*")
	if t.ObjectLock != "" && retainUntil != nil {
		hdr.Set("X-Amz-Object-Lock-Mode", t.ObjectLock)
		hdr.Set("X-Amz-Object-Lock-Retain-Until-Date", retainUntil.UTC().Format(time.RFC3339))
	}
	res, err := t.do(ctx, http.MethodPut, u, r, size, "UNSIGNED-PAYLOAD", hdr)
	if err != nil {
		return err
	}
	res.Body.Close()
	return nil
}

func (t *S3Target) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	u, err := t.objectURL(key, nil)
	if err != nil {
		return nil, err
	}
	res, err := t.do(ctx, http.MethodGet, u, nil, -1, emptySHA256, nil)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

func (t *S3Target) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		u, err := t.objectURL("", q)
		if err != nil {
			return nil, err
		}
		res, err := t.do(ctx, http.MethodGet, u, nil, -1, emptySHA256, nil)
		if err != nil {
			return nil, err
		}
		var lr struct {
			Contents []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
		}
		err = xml.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&lr)
		res.Body.Close()
		if err != nil {
			return nil, err
		}
		for _, c := range lr.Contents {
			out = append(out, c.Key)
		}
		if !lr.IsTruncated || lr.NextContinuationToken == "" {
			break
		}
		token = lr.NextContinuationToken
	}
	sort.Strings(out)
	return out, nil
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func hmacSHA256(k []byte, s string) []byte {
	h := hmac.New(sha256.New, k)
	h.Write([]byte(s))
	return h.Sum(nil)
}

func uriEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || (keepSlash && c == '/') {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// SignV4 adds AWS Signature Version 4 headers to req.
func SignV4(req *http.Request, accessKey, secretKey, region, service, payloadHash string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	host := req.URL.Host
	req.Host = host

	// Canonical query string.
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qs []string
	for _, k := range keys {
		vs := q[k]
		sort.Strings(vs)
		for _, v := range vs {
			qs = append(qs, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	// Canonical headers: host + all x-amz-* + content-type.
	hdrs := map[string]string{"host": host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-type" || lk == "if-none-match" {
			hdrs[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k + ":" + hdrs[k] + "\n")
	}
	signed := strings.Join(names, ";")
	p := req.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	canonPath := uriEncode(unescapePath(p), true)
	canonical := strings.Join([]string{req.Method, canonPath, strings.Join(qs, "&"), ch.String(), signed, payloadHash}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	k := hmacSHA256([]byte("AWS4"+secretKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

func unescapePath(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		return u
	}
	return p
}
