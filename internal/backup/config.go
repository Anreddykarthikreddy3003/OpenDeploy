package backup

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
)

// TargetFromConfig builds the configured target and object prefix.
func TargetFromConfig(c config.BackupConfig) (Target, string, error) {
	if c.Endpoint == "" {
		if c.LocalDir == "" {
			return nil, "", errors.New("backup: configure backup.endpoint (S3) or backup.local_dir")
		}
		return &LocalTarget{Dir: c.LocalDir}, c.Prefix, nil
	}
	if c.Bucket == "" {
		return nil, "", errors.New("backup: bucket is required with an S3 endpoint")
	}
	read := func(p string) (string, error) {
		if p == "" {
			return "", errors.New("backup: access_key_file and secret_key_file are required for S3")
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("backup credentials: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	ak, err := read(c.AccessKey)
	if err != nil {
		return nil, "", err
	}
	sk, err := read(c.SecretKey)
	if err != nil {
		return nil, "", err
	}
	ep := c.Endpoint
	if !strings.Contains(ep, "://") {
		scheme := "https://"
		if c.UseSSL != nil && !*c.UseSSL {
			scheme = "http://"
		}
		ep = scheme + ep
	}
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}
	t := &S3Target{Endpoint: ep, Region: region, Bucket: c.Bucket, AccessKey: ak, SecretKey: sk}
	if c.ObjectLock {
		t.ObjectLock = "COMPLIANCE"
	}
	return t, c.Prefix, nil
}

// RetainUntil computes the object-lock retention for a new backup.
func RetainUntil(c config.BackupConfig, now time.Time) *time.Time {
	if !c.ObjectLock || c.RetainDays <= 0 {
		return nil
	}
	t := now.Add(time.Duration(c.RetainDays) * 24 * time.Hour).UTC()
	return &t
}

// UnwrapDEK returns a manifest's data key (restore tooling).
func UnwrapDEK(m *Manifest, master MasterKey) ([]byte, error) {
	if m.MasterKeyID != master.ID() {
		return nil, fmt.Errorf("backup %s was encrypted with master key %s, not %s", m.ID, m.MasterKeyID, master.ID())
	}
	w, err := decodeB64(m.WrappedDEK)
	if err != nil {
		return nil, err
	}
	return Unwrap(master[:], w, "dek:"+m.ID)
}
