package artifact

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dg(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

type layout struct {
	files map[string][]byte
	order []string
}

func (l *layout) add(name string, b []byte) {
	if l.files == nil {
		l.files = map[string][]byte{}
	}
	l.files[name] = b
	l.order = append(l.order, name)
}

func (l *layout) tar(extra func(tw *tar.Writer)) *bytes.Buffer {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range l.order {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(l.files[n])), Typeflag: tar.TypeReg})
		_, _ = tw.Write(l.files[n])
	}
	if extra != nil {
		extra(tw)
	}
	tw.Close()
	return &buf
}

// makeImage builds a valid single-manifest OCI layout; mutate lets tests
// tamper with the manifest before it is serialised.
func makeImage(t *testing.T, mutate func(m map[string]any)) (*layout, string) {
	t.Helper()
	layer := []byte("layer-bytes")
	cfg, _ := json.Marshal(map[string]any{"architecture": "amd64", "os": "linux", "config": map[string]any{"User": "10001", "ExposedPorts": map[string]any{"8080/tcp": map[string]any{}}}})
	m := map[string]any{
		"schemaVersion": 2, "mediaType": MediaOCIManifest,
		"config": map[string]any{"mediaType": MediaOCIConfig, "digest": dg(cfg), "size": len(cfg)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": dg(layer), "size": len(layer)}},
	}
	if mutate != nil {
		mutate(m)
	}
	mb, _ := json.Marshal(m)
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": MediaOCIManifest, "digest": dg(mb), "size": len(mb)}}})
	l := &layout{}
	l.add("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	l.add("index.json", idx)
	for _, b := range [][]byte{layer, cfg, mb} {
		l.add("blobs/sha256/"+strings.TrimPrefix(dg(b), "sha256:"), b)
	}
	return l, dg(mb)
}

func newStore(t *testing.T) *Store {
	s, err := NewStore(t.TempDir(), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIngestValidImage(t *testing.T) {
	s := newStore(t)
	l, md := makeImage(t, nil)
	info, err := s.IngestOCILayout(l.tar(nil))
	if err != nil {
		t.Fatal(err)
	}
	if info.Digest != md || info.User != "10001" || len(info.ExposedPorts) != 1 || len(info.Warnings) != 0 {
		t.Fatalf("%+v", info)
	}
}

func TestIngestRejectsTamperedBlob(t *testing.T) {
	s := newStore(t)
	l, _ := makeImage(t, nil)
	for n := range l.files {
		if strings.HasPrefix(n, "blobs/") {
			l.files[n] = append([]byte("evil"), l.files[n]...)
			break
		}
	}
	if _, err := s.IngestOCILayout(l.tar(nil)); err == nil {
		t.Fatal("tampered blob accepted")
	}
}

func TestIngestRejectsForeignLayerAndBadMedia(t *testing.T) {
	s := newStore(t)
	l, _ := makeImage(t, func(m map[string]any) {
		m["layers"].([]any)[0].(map[string]any)["urls"] = []string{"http://169.254.169.254/"}
	})
	if _, err := s.IngestOCILayout(l.tar(nil)); err == nil {
		t.Fatal("foreign layer accepted")
	}
	l2, _ := makeImage(t, func(m map[string]any) {
		m["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/x-sh"
	})
	if _, err := s.IngestOCILayout(l2.tar(nil)); err == nil {
		t.Fatal("bad media type accepted")
	}
}

func TestIngestRejectsMissingBlobAndSizeMismatch(t *testing.T) {
	s := newStore(t)
	l, _ := makeImage(t, func(m map[string]any) {
		m["layers"].([]any)[0].(map[string]any)["size"] = 1
	})
	if _, err := s.IngestOCILayout(l.tar(nil)); err == nil {
		t.Fatal("size mismatch accepted")
	}
	l2, _ := makeImage(t, func(m map[string]any) {
		m["layers"] = append(m["layers"].([]any), map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": dg([]byte("nope")), "size": 4})
	})
	if _, err := s.IngestOCILayout(l2.tar(nil)); err == nil {
		t.Fatal("missing blob accepted")
	}
}

func TestIngestRejectsSymlinksAndExtras(t *testing.T) {
	s := newStore(t)
	l, _ := makeImage(t, nil)
	buf := l.tar(func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "blobs/sha256/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"})
	})
	if _, err := s.IngestOCILayout(buf); err == nil {
		t.Fatal("symlink accepted")
	}
	l2, _ := makeImage(t, nil)
	l2.add("../../etc/cron.d/x", []byte("x"))
	if _, err := s.IngestOCILayout(l2.tar(nil)); err == nil {
		t.Fatal("unexpected entry accepted")
	}
}

func TestRootImageWarns(t *testing.T) {
	s := newStore(t)
	layer := []byte("l")
	cfg, _ := json.Marshal(map[string]any{"os": "linux", "config": map[string]any{}})
	l, _ := makeImage(t, func(m map[string]any) {
		m["config"] = map[string]any{"mediaType": MediaOCIConfig, "digest": dg(cfg), "size": len(cfg)}
		m["layers"] = []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": dg(layer), "size": len(layer)}}
	})
	l.add("blobs/sha256/"+strings.TrimPrefix(dg(cfg), "sha256:"), cfg)
	l.add("blobs/sha256/"+strings.TrimPrefix(dg(layer), "sha256:"), layer)
	info, err := s.IngestOCILayout(l.tar(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Warnings) == 0 {
		t.Fatal("root image should warn")
	}
}

func staticTar(entries []tar.Header, bodies map[string]string) *bytes.Buffer {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		b := bodies[h.Name]
		h.Size = int64(len(b))
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		_ = tw.WriteHeader(&h)
		if h.Typeflag == tar.TypeReg {
			_, _ = io.WriteString(tw, b)
		}
	}
	tw.Close()
	return &buf
}

func TestIngestStatic(t *testing.T) {
	s := newStore(t)
	buf := staticTar([]tar.Header{{Name: "./", Typeflag: tar.TypeDir}, {Name: "./index.html", Typeflag: tar.TypeReg, Mode: 0o777}, {Name: "assets/app.js", Typeflag: tar.TypeReg}},
		map[string]string{"./index.html": "<h1>hi</h1>", "assets/app.js": "x"})
	info, err := s.IngestStatic(buf)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(s.StaticDir(info.Digest), "index.html"))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("%v %v", fi, err)
	}
	// Same content in different order and metadata yields the same digest.
	buf2 := staticTar([]tar.Header{{Name: "assets/app.js", Typeflag: tar.TypeReg, Mode: 0o600}, {Name: "index.html", Typeflag: tar.TypeReg}},
		map[string]string{"index.html": "<h1>hi</h1>", "assets/app.js": "x"})
	info2, err := s.IngestStatic(buf2)
	if err != nil || info2.Digest != info.Digest {
		t.Fatalf("digest not deterministic: %v %v", info2, err)
	}
}

func TestIngestStaticRejects(t *testing.T) {
	s := newStore(t)
	cases := map[string][]tar.Header{
		"traversal": {{Name: "../../etc/passwd", Typeflag: tar.TypeReg}},
		"symlink":   {{Name: "index.html", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}},
		"hardlink":  {{Name: "index.html", Typeflag: tar.TypeLink, Linkname: "/etc/shadow"}},
		"device":    {{Name: "dev", Typeflag: tar.TypeChar}},
		"empty":     {},
		"dup":       {{Name: "a", Typeflag: tar.TypeReg}, {Name: "./a", Typeflag: tar.TypeReg}},
	}
	for name, hs := range cases {
		if _, err := s.IngestStatic(staticTar(hs, map[string]string{"../../etc/passwd": "x", "a": "1", "./a": "2"})); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRegistryAuthAndScope(t *testing.T) {
	s := newStore(t)
	l, md := makeImage(t, nil)
	if _, err := s.IngestOCILayout(l.tar(nil)); err != nil {
		t.Fatal(err)
	}
	_ = s.Tag("od/prj-a", "v1", md)
	reg := NewRegistry(s, "pulltok", nil)
	srv := httptest.NewServer(reg)
	defer srv.Close()
	get := func(user, pass, path string) int {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if get("", "", "/v2/od/prj-a/manifests/v1") != 401 {
		t.Fatal("anonymous pull allowed")
	}
	if get("runtime", "wrong", "/v2/od/prj-a/manifests/v1") != 401 {
		t.Fatal("wrong token allowed")
	}
	if code := get("runtime", "pulltok", "/v2/od/prj-a/manifests/v1"); code != 200 {
		t.Fatalf("pull failed %d", code)
	}
	// Push token for project B cannot push to project A.
	tok, _ := reg.GrantPush("od/prj-b", 60e9)
	req, _ := http.NewRequest("POST", srv.URL+"/v2/od/prj-a/blobs/uploads/", nil)
	req.SetBasicAuth("push", tok)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("cross-repo push status %d", res.StatusCode)
	}
	// Pull credential cannot push.
	req, _ = http.NewRequest("POST", srv.URL+"/v2/od/prj-a/blobs/uploads/", nil)
	req.SetBasicAuth("runtime", "pulltok")
	res, _ = http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("pull credential push status %d", res.StatusCode)
	}
}

func TestRegistryPushFlowValidatesManifest(t *testing.T) {
	s := newStore(t)
	reg := NewRegistry(s, "p", nil)
	srv := httptest.NewServer(reg)
	defer srv.Close()
	tok, _ := reg.GrantPush("od/prj-a", 60e9)
	do := func(method, path string, body []byte, ct string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		req.SetBasicAuth("push", tok)
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	push := func(b []byte) {
		res := do("POST", "/v2/od/prj-a/blobs/uploads/", nil, "")
		loc := res.Header.Get("Location")
		do("PATCH", loc, b, "application/octet-stream")
		if r := do("PUT", loc+"?digest="+dg(b), nil, ""); r.StatusCode != 201 {
			t.Fatalf("blob put %d", r.StatusCode)
		}
	}
	layer := []byte("L")
	cfg, _ := json.Marshal(map[string]any{"os": "linux", "config": map[string]any{"User": "1000"}})
	m, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": MediaOCIManifest,
		"config": map[string]any{"mediaType": MediaOCIConfig, "digest": dg(cfg), "size": len(cfg)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": dg(layer), "size": len(layer)}}})
	// Manifest before blobs: rejected.
	if r := do("PUT", "/v2/od/prj-a/manifests/dep_x", m, MediaOCIManifest); r.StatusCode != 400 {
		t.Fatalf("manifest with missing blobs accepted: %d", r.StatusCode)
	}
	push(layer)
	push(cfg)
	if r := do("PUT", "/v2/od/prj-a/manifests/dep_x", m, MediaOCIManifest); r.StatusCode != 201 {
		t.Fatalf("manifest put %d", r.StatusCode)
	}
	info, err := s.ValidateTagged("od/prj-a", "dep_x")
	if err != nil || info.Digest != dg(m) {
		t.Fatalf("%+v %v", info, err)
	}
	// Wrong digest on blob upload rejected.
	res := do("POST", "/v2/od/prj-a/blobs/uploads/", nil, "")
	if r := do("PUT", res.Header.Get("Location")+"?digest="+dg([]byte("other")), []byte("data"), ""); r.StatusCode != 400 {
		t.Fatal("digest mismatch accepted")
	}
}

func TestGCKeepsReachable(t *testing.T) {
	s := newStore(t)
	l, md := makeImage(t, nil)
	if _, err := s.IngestOCILayout(l.tar(nil)); err != nil {
		t.Fatal(err)
	}
	orphan, _, _ := s.PutBlob(strings.NewReader("orphan"), "", 100)
	// Age every blob past the in-flight guard.
	old := int64(1)
	_ = filepath.Walk(filepath.Join(s.Root, "blobs"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			_ = os.Chtimes(p, timeUnix(old), timeUnix(old))
		}
		return nil
	})
	svc := &Service{Store: s}
	res, err := svc.GC(nil, GCReq{KeepImages: []string{md}})
	if err != nil {
		t.Fatal(err)
	}
	if res.RemovedBlobs != 1 {
		t.Fatalf("%+v", res)
	}
	if _, ok := s.HasBlob(orphan); ok {
		t.Fatal("orphan not removed")
	}
	if _, ok := s.HasBlob(md); !ok {
		t.Fatal("kept manifest removed")
	}
}

func timeUnix(s int64) time.Time { return time.Unix(s, 0) }
