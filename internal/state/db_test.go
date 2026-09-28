package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func open(t *testing.T, path string, fs fstest.MapFS) *DB {
	t.Helper()
	db, err := Open(context.Background(), path, Options{Migrations: fs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrationsApplyAndTamperDetect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	v1 := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a(x INTEGER);")}}
	db := open(t, path, v1)
	if db.Degraded() != "" {
		t.Fatal(db.Degraded())
	}
	if v, _ := db.SchemaVersion(context.Background()); v != 1 {
		t.Fatalf("version %d", v)
	}
	db.Close()

	tampered := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a(x TEXT);")}}
	db2 := open(t, path, tampered)
	if db2.Degraded() == "" {
		t.Fatal("checksum mismatch must degrade")
	}
	if err := db2.Tx(context.Background(), func(*sqlTx) error { return nil }); !errors.Is(err, ErrDegraded) {
		t.Fatalf("got %v", err)
	}
}

func TestNewerSchemaDegrades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	v2 := fstest.MapFS{
		"0001_a.sql": {Data: []byte("CREATE TABLE a(x INTEGER);")},
		"0002_b.sql": {Data: []byte("CREATE TABLE b(x INTEGER);")},
	}
	open(t, path, v2).Close()
	v1 := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a(x INTEGER);")}}
	if open(t, path, v1).Degraded() == "" {
		t.Fatal("downgrade must degrade")
	}
}

func TestNonContiguousMigrationsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	bad := fstest.MapFS{"0002_a.sql": {Data: []byte("SELECT 1;")}}
	if _, err := Open(context.Background(), path, Options{Migrations: bad}); err == nil {
		t.Fatal("expected error")
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	bad := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a(x INTEGER); CREATE TABLE a(y INTEGER);")}}
	if _, err := Open(context.Background(), path, Options{Migrations: bad}); err == nil {
		t.Fatal("expected error")
	}
	good := fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE a(x INTEGER);")}}
	if open(t, path, good).Degraded() != "" {
		t.Fatal("partial migration leaked")
	}
}
