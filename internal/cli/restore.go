package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/backup"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/restore"
)

func cmdRestore(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultPath, "node configuration of the node being restored")
	from := fs.String("from", "", "local backup directory (default: the target configured in node.yaml)")
	id := fs.String("id", "latest", "backup id")
	keyFile := fs.String("master-key", "", "file with the backup master key (hex); '-' reads stdin")
	signer := fs.String("signer", "", "expected manifest signer public key (base64); defaults to backup.signer_public_key")
	list := fs.Bool("list", false, "list available backups and exit")
	force := fs.Bool("force", false, "overwrite existing platform state")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	n, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	var target backup.Target
	prefix := n.Backup.Prefix
	if *from != "" {
		target = &backup.LocalTarget{Dir: *from}
	} else {
		target, prefix, err = backup.TargetFromConfig(n.Backup)
		if err != nil {
			return err
		}
	}
	if *list {
		ids, err := backup.List(ctx, target, prefix)
		if err != nil {
			return err
		}
		rows := [][]string{{"ID", "CREATED", "SIZE", "VERSION", "COMPONENTS"}}
		for _, i := range ids {
			m, err := backup.ReadManifest(ctx, target, prefix, i, nil)
			if err != nil {
				rows = append(rows, []string{i, "INVALID: " + err.Error(), "", "", ""})
				continue
			}
			rows = append(rows, []string{i, m.CreatedAt.Format("2006-01-02 15:04"), fmt.Sprintf("%d MiB", m.CipherSize>>20), m.Version, fmt.Sprint(len(m.Components))})
		}
		table(rows)
		return nil
	}
	if *keyFile == "" {
		return errors.New("--master-key is required (the key exported from Platform → Backups)")
	}
	var raw []byte
	if *keyFile == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 256))
	} else {
		raw, err = os.ReadFile(*keyFile)
	}
	if err != nil {
		return err
	}
	mk, err := backup.ParseMasterKey(string(raw))
	if err != nil {
		return err
	}
	pin := *signer
	if pin == "" {
		pin = n.Backup.SignerPublicKey
	}
	var pub ed25519.PublicKey
	if pin != "" {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pin))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return errors.New("--signer must be a base64 Ed25519 public key")
		}
		pub = b
	} else {
		fmt.Fprintln(os.Stderr, "warning: no pinned signer (--signer); accepting the key embedded in the manifest")
	}
	_, err = restore.Run(ctx, restore.Options{Node: n, Target: target, Prefix: prefix, ID: *id, Master: mk, Signer: pub, Force: *force, Out: os.Stdout})
	if err != nil {
		return err
	}
	fmt.Println("\nNext: fix ownership (`systemd-tmpfiles --create`), start OpenDeploy, then sign in. The reconciler restarts workloads from the restored desired state.")
	return nil
}
