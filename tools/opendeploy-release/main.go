// Command opendeploy-release maintains the OpenDeploy TUF update repository
// (release engineering tool; not shipped to nodes).
//
//	opendeploy-release init      --repo DIR --keys DIR [--root-keys 3 --root-threshold 2]
//	opendeploy-release publish   --repo DIR --keys DIR --channel stable --version 2.1.0 --schema 1 \
//	                             --artifact linux-amd64=dist/opendeploy_2.1.0_linux_amd64.tar.gz ...
//	opendeploy-release timestamp --repo DIR --keys DIR          (run daily: freshness)
//	opendeploy-release halt      --repo DIR --keys DIR --channel stable
//	opendeploy-release revoke    --repo DIR --keys DIR --channel stable --version 2.0.1
//
// Keys are ed25519 seeds in DIR/<role>-<n>.key. Keep root keys offline (on
// separate hardware, threshold-signed); `init` is the only command that
// needs them. The online roles (targets, snapshot, timestamp) can live in
// CI secrets.
package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/update"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func loadKeys(dir string, roles ...string) (map[string][]ed25519.PrivateKey, error) {
	out := map[string][]ed25519.PrivateKey{}
	for _, role := range roles {
		matches, _ := filepath.Glob(filepath.Join(dir, role+"-*.key"))
		sort.Strings(matches)
		for _, m := range matches {
			k, err := update.LoadKey(m)
			if err != nil {
				return nil, err
			}
			out[role] = append(out[role], k)
		}
		if len(out[role]) == 0 {
			return nil, fmt.Errorf("no %s keys in %s", role, dir)
		}
	}
	return out, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: opendeploy-release init|publish|timestamp|halt|revoke [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	repo := fs.String("repo", "tuf-repo", "repository directory (metadata/ and targets/)")
	keys := fs.String("keys", "tuf-keys", "key directory")
	rootKeys := fs.Int("root-keys", 3, "number of root keys (init)")
	rootThreshold := fs.Int("root-threshold", 2, "root signature threshold (init)")
	channel := fs.String("channel", "stable", "release channel")
	version := fs.String("version", "", "release version")
	schema := fs.Int("schema", 1, "platform schema version of the release")
	notes := fs.String("notes", "", "release notes")
	var artifacts multi
	fs.Var(&artifacts, "artifact", "platform=path (repeatable)")
	_ = fs.Parse(os.Args[2:])
	if err := run(cmd, *repo, *keys, *rootKeys, *rootThreshold, *channel, *version, *schema, *notes, artifacts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(cmd, repo, keyDir string, rootKeys, rootThreshold int, channel, version string, schema int, notes string, artifacts []string) error {
	switch cmd {
	case "init":
		if _, err := os.Stat(filepath.Join(repo, "metadata", "root.json")); err == nil {
			return errors.New("repository already initialised")
		}
		ks := map[string][]ed25519.PrivateKey{}
		counts := map[string]int{"root": rootKeys, "targets": 1, "snapshot": 1, "timestamp": 1}
		for role, n := range counts {
			for i := 1; i <= n; i++ {
				k, err := update.GenerateKey(filepath.Join(keyDir, fmt.Sprintf("%s-%d.key", role, i)))
				if err != nil {
					return err
				}
				ks[role] = append(ks[role], k)
			}
		}
		if _, err := update.InitRepository(repo, ks, rootThreshold); err != nil {
			return err
		}
		fmt.Printf("Initialised %s (root %d-of-%d). Ship %s as the nodes' trusted root.\nMove %s/root-*.key offline now.\n",
			repo, rootThreshold, rootKeys, filepath.Join(repo, "metadata", "1.root.json"), keyDir)
		return nil
	case "publish", "timestamp", "halt", "revoke":
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
	ks, err := loadKeys(keyDir, "targets", "snapshot", "timestamp")
	if err != nil {
		return err
	}
	p, err := update.LoadPublisher(repo, ks)
	if err != nil {
		return err
	}
	switch cmd {
	case "publish":
		if version == "" || len(artifacts) == 0 {
			return errors.New("--version and at least one --artifact are required")
		}
		files := map[string][]byte{}
		for _, a := range artifacts {
			plat, path, ok := strings.Cut(a, "=")
			if !ok {
				return fmt.Errorf("bad --artifact %q (want platform=path)", a)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[plat] = b
		}
		var revoked []string
		if prev, err := p.ReadChannel(channel); err == nil {
			revoked = prev.Revoked
		}
		if err := p.PublishRelease(update.Release{Version: version, Channel: channel, SchemaVersion: schema, Notes: notes, Revoked: revoked}, files); err != nil {
			return err
		}
		fmt.Printf("Published %s to %s\n", version, channel)
	case "timestamp":
		if err := p.BumpTimestamp(); err != nil {
			return err
		}
		fmt.Println("Timestamp re-signed")
	case "halt":
		r, err := p.ReadChannel(channel)
		if err != nil {
			return err
		}
		r.Halted = true
		if err := p.SetChannel(*r); err != nil {
			return err
		}
		fmt.Printf("Halted %s on %s: nodes will not stage it\n", r.Version, channel)
	case "revoke":
		r, err := p.ReadChannel(channel)
		if err != nil {
			return err
		}
		if version == "" {
			return errors.New("--version is required")
		}
		r.Revoked = append(r.Revoked, version)
		if r.Version == version {
			r.Halted = true
		}
		if err := p.SetChannel(*r); err != nil {
			return err
		}
		fmt.Printf("Revoked %s on %s\n", version, channel)
	}
	return nil
}
