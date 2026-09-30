package builder

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/detect"
)

func TestWriteBuildCAMergesSystemRoots(t *testing.T) {
	dir := t.TempDir()
	extra := filepath.Join(dir, "corp.pem")
	caPEM, _, _ := testCA(t)
	_ = os.WriteFile(extra, caPEM, 0o644)
	p, only, err := writeBuildCA(dir, extra)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(only); !bytes.Equal(b, caPEM) {
		t.Fatal("extra-only bundle is not exactly the configured CAs")
	}
	b, _ := os.ReadFile(p)
	if !bytes.HasSuffix(bytes.TrimSpace(b), bytes.TrimSpace(caPEM)) {
		t.Fatal("extra CA missing from the bundle")
	}
	for _, f := range systemRootFiles {
		if sys, err := os.ReadFile(f); err == nil {
			if !bytes.HasPrefix(b, sys) {
				t.Fatal("system roots missing from the bundle")
			}
			break
		}
	}
	_ = os.WriteFile(extra, []byte("not a cert"), 0o644)
	if _, _, err := writeBuildCA(dir, extra); err == nil {
		t.Fatal("non-PEM bundle accepted")
	}
}

func testCA(t *testing.T) (caPEM []byte, ca *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OpenDeploy test inspection CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca, key
}

// A build step behind TLS inspection: the RUN fetch only succeeds when the
// generated Dockerfile is rewritten to trust the node's build CA, and the CA
// never ends up in the image.
func TestDockerBuildTrustsBuildCA(t *testing.T) {
	if os.Getenv("OPENDEPLOY_DOCKER_TESTS") != "1" {
		t.Skip("set OPENDEPLOY_DOCKER_TESTS=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	gw := dockerGateway(t)
	caPEM, ca, caKey := testCA(t)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: gw.String()}, IPAddresses: []net.IP{gw},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(gw.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on the docker gateway: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("package index")) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	url := "https://" + ln.Addr().String() + "/"

	// The fetcher stands in for npm/pip: a static Go binary using the
	// platform roots (and therefore SSL_CERT_FILE).
	ctxDir := t.TempDir()
	fetcher := filepath.Join(ctxDir, "fetch")
	src := filepath.Join(t.TempDir(), "main.go")
	_ = os.WriteFile(src, []byte(`package main
import ("fmt";"io";"net/http";"os")
func main(){r,err:=http.Get(os.Args[1]);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)};b,_:=io.ReadAll(r.Body);fmt.Println(string(b))}
`), 0o644)
	build := exec.Command("go", "build", "-o", fetcher, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fetcher: %v %s", err, out)
	}
	extra := filepath.Join(t.TempDir(), "corp.pem")
	_ = os.WriteFile(extra, caPEM, 0o644)
	bundle, extraOnly, err := writeBuildCA(t.TempDir(), extra)
	if err != nil {
		t.Fatal(err)
	}
	base := "FROM alpine:3.20\nCOPY fetch /fetch\nRUN /fetch " + url + " > /index.txt\n"
	ex := &DockerBuildx{}
	try := func(df string, secrets map[string]string) (string, error) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0o644)
		var log bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		err := ex.Build(ctx, Spec{ContextDir: ctxDir, DockerfileDir: dir, Dockerfile: "Dockerfile", Output: OutputTar,
			Dest: filepath.Join(dir, "out.tar"), Secrets: secrets}, &log)
		return log.String(), err
	}
	if logs, err := try(base+"# plain\n", nil); err == nil {
		t.Fatalf("fetch through the inspecting server succeeded without the CA:\n%s", logs)
	} else if !strings.Contains(logs, "certificate") {
		t.Fatalf("failed for another reason: %v\n%s", err, logs)
	}
	secrets := map[string]string{detect.BuildCASecretID: bundle, detect.BuildCAExtraSecretID: extraOnly}
	df := detect.WithBuildCA(base)
	if logs, err := try(df, secrets); err != nil {
		t.Fatalf("build with the CA failed: %v\n%s", err, logs)
	}
	// JVM tools ignore the SSL_CERT_FILE family: the step must import the
	// CA into a throwaway trust store (Maven/Gradle behind a TLS proxy).
	_ = os.WriteFile(filepath.Join(ctxDir, "Fetch.java"), []byte(`public class Fetch {
	public static void main(String[] a) throws Exception {
		var r = java.net.http.HttpClient.newHttpClient().send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(a[0])).build(),
			java.net.http.HttpResponse.BodyHandlers.ofString());
		System.out.println("status " + r.statusCode());
	}
}
`), 0o644)
	jbase := "FROM eclipse-temurin:21-jdk\nCOPY Fetch.java /Fetch.java\nRUN java /Fetch.java " + url + "\n"
	if logs, err := try(jbase+"# plain\n", nil); err == nil {
		t.Fatalf("Java fetch through the inspecting server succeeded without the CA:\n%s", logs)
	} else if !strings.Contains(logs, "PKIX") && !strings.Contains(logs, "certification path") {
		t.Fatalf("Java failed for another reason: %v\n%s", err, logs)
	}
	if logs, err := try(detect.WithBuildCA(jbase), secrets); err != nil || !strings.Contains(logs, "status 200") {
		t.Fatalf("Java build with the CA failed: %v\n%s", err, logs)
	}
}

func dockerGateway(t *testing.T) net.IP {
	out, err := exec.Command("docker", "network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}").Output()
	ip := net.ParseIP(strings.TrimSpace(string(out)))
	if err != nil || ip == nil {
		t.Skip(fmt.Sprintf("no docker bridge gateway: %v", err))
	}
	return ip
}
