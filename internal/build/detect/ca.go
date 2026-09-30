package detect

import (
	"regexp"
	"strings"
)

// Enterprise TLS inspection (build.ca_bundle): builderd passes a complete
// trust bundle (system roots + the corporate CA) to BuildKit as the build
// secret BuildCASecretID. Generated Dockerfiles mount it into every RUN step
// and point the common toolchains at it for that step only, so package
// installs work behind an inspecting proxy while nothing is written into an
// image layer. Custom Dockerfiles opt in with the same mount:
//
//	RUN --mount=type=secret,id=opendeploy-ca,target=/run/secrets/opendeploy-ca \
//	    SSL_CERT_FILE=/run/secrets/opendeploy-ca npm ci
const (
	BuildCASecretID = "opendeploy-ca"
	BuildCAPath     = "/run/secrets/opendeploy-ca"
	// BuildCAExtraSecretID carries only the operator's extra CAs, for
	// toolchains that extend a trust store instead of replacing it (Java).
	BuildCAExtraSecretID = "opendeploy-ca-extra"
	BuildCAExtraPath     = "/run/secrets/opendeploy-ca-extra"
	buildCAJavaDir       = "/run/opendeploy-jks"
)

// javaTrust makes JVM tools (Maven, Gradle, sbt) trust the extra CAs: the
// JVM ignores the variables above, so the step imports them into a copy of
// the JDK's default trust store on a tmpfs and points JAVA_TOOL_OPTIONS at
// it. It is a no-op in images without a JDK.
const javaTrust = `if command -v keytool >/dev/null 2>&1; then ` +
	`od_jh=$(dirname "$(dirname "$(readlink -f "$(command -v keytool)")")"); ` +
	`cp "$od_jh/lib/security/cacerts" ` + buildCAJavaDir + `/cacerts && ` +
	`awk '/BEGIN CERTIFICATE/{n++} n{print > ("` + buildCAJavaDir + `/ca" n ".pem")}' ` + BuildCAExtraPath + ` && ` +
	`for od_f in ` + buildCAJavaDir + `/ca*.pem; do keytool -importcert -noprompt -storepass changeit -keystore ` + buildCAJavaDir + `/cacerts ` +
	`-alias "opendeploy-$(basename "$od_f" .pem)" -file "$od_f" >/dev/null; done; ` +
	`export JAVA_TOOL_OPTIONS="-Djavax.net.ssl.trustStore=` + buildCAJavaDir + `/cacerts -Djavax.net.ssl.trustStorePassword=changeit ${JAVA_TOOL_OPTIONS:-}"; fi; `

// buildCAEnv are the variables that make common toolchains trust the bundle.
// All of them take a complete bundle (they replace, not extend, the default
// roots), which is why builderd merges the system roots in.
var buildCAEnv = []string{
	"SSL_CERT_FILE",       // OpenSSL, Go, .NET, Python ssl, Ruby
	"NODE_EXTRA_CA_CERTS", // Node.js (additive)
	"REQUESTS_CA_BUNDLE",  // Python requests
	"PIP_CERT",            // pip
	"CURL_CA_BUNDLE",      // curl
	"GIT_SSL_CAINFO",      // git
	"CARGO_HTTP_CAINFO",   // cargo
	"BUNDLE_SSL_CA_CERT",  // bundler
	"COMPOSER_CAFILE",     // composer
	"HEX_CACERTS_PATH",    // mix/hex
	"NPM_CONFIG_CAFILE",   // npm (replaces its bundled roots)
	"YARN_CA_FILE_PATH",   // yarn
}

var runFlag = regexp.MustCompile(`^--[a-z-]+=\S+\s+`)

// WithBuildCA rewrites the shell-form RUN instructions of a generated
// Dockerfile to mount and use the build CA bundle.
func WithBuildCA(dockerfile string) string {
	var exports strings.Builder
	exports.WriteString("export")
	for _, v := range buildCAEnv {
		exports.WriteString(" " + v + "=" + BuildCAPath)
	}
	exports.WriteString("; ")
	exports.WriteString(javaTrust)
	mount := "--mount=type=secret,id=" + BuildCASecretID + ",target=" + BuildCAPath + " " +
		"--mount=type=secret,id=" + BuildCAExtraSecretID + ",target=" + BuildCAExtraPath + " " +
		"--mount=type=tmpfs,target=" + buildCAJavaDir + " "

	lines := strings.Split(dockerfile, "\n")
	continued := false
	for i, line := range lines {
		wasContinued := continued
		continued = strings.HasSuffix(strings.TrimRight(line, " \t"), "\\")
		if wasContinued {
			continue
		}
		trimmed := strings.TrimLeft(line, " \t")
		if len(trimmed) < 4 || !strings.EqualFold(trimmed[:4], "RUN ") {
			continue
		}
		indent := line[:len(line)-len(trimmed)]
		rest := strings.TrimLeft(trimmed[4:], " ")
		if strings.HasPrefix(rest, "[") {
			continue // exec form: no shell to export into
		}
		var flags strings.Builder
		for {
			m := runFlag.FindString(rest)
			if m == "" {
				break
			}
			flags.WriteString(m)
			rest = rest[len(m):]
		}
		lines[i] = indent + "RUN " + mount + flags.String() + exports.String() + rest
	}
	return strings.Join(lines, "\n")
}
