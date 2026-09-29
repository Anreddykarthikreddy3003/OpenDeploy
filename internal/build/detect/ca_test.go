package detect

import (
	"strings"
	"testing"
)

func TestWithBuildCA(t *testing.T) {
	in := "FROM node:22 AS build\n" +
		"RUN --mount=type=cache,target=/root/.npm npm ci && \\\n    RUN_NOT_AN_INSTRUCTION=1 npm run build\n" +
		"RUN [\"/bin/true\"]\n" +
		"  run apt-get update\n" +
		"COPY . .\n"
	out := WithBuildCA(in)
	lines := strings.Split(out, "\n")
	mount := "--mount=type=secret,id=opendeploy-ca,target=/run/secrets/opendeploy-ca "
	if !strings.HasPrefix(lines[1], "RUN "+mount+"--mount=type=cache,target=/root/.npm export SSL_CERT_FILE=/run/secrets/opendeploy-ca") ||
		!strings.HasSuffix(lines[1], "; npm ci && \\") {
		t.Fatalf("shell RUN not rewritten: %q", lines[1])
	}
	if lines[2] != "    RUN_NOT_AN_INSTRUCTION=1 npm run build" {
		t.Fatalf("continuation line touched: %q", lines[2])
	}
	if lines[3] != `RUN ["/bin/true"]` {
		t.Fatalf("exec form touched: %q", lines[3])
	}
	if !strings.HasPrefix(lines[4], "  RUN "+mount+"export ") || !strings.HasSuffix(lines[4], "; apt-get update") {
		t.Fatalf("indented lower-case RUN: %q", lines[4])
	}
	if !strings.Contains(lines[1], "NODE_EXTRA_CA_CERTS=/run/secrets/opendeploy-ca") {
		t.Fatal("node variable missing")
	}
	if strings.Count(out, "ENV ") != 0 {
		t.Fatal("CA must never be persisted with ENV")
	}
}

// Every generated template must stay valid after the rewrite: each RUN line
// gains exactly one secret mount.
func TestWithBuildCAOnGeneratedPlans(t *testing.T) {
	for _, df := range []string{renderCustom(&Plan{Port: 8080, StartCommand: "./app", BuildCommand: "make"}, "")} {
		out := WithBuildCA(df)
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "RUN ") && !strings.HasPrefix(l, "RUN [") && strings.Count(l, "id=opendeploy-ca") != 1 {
				t.Fatalf("RUN line without exactly one CA mount: %q", l)
			}
		}
	}
}
