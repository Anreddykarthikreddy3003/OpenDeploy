// Package schema holds the platform database schema version without
// importing the database layer, so tools on every OS can report it.
package schema

// Version is the latest platform schema migration. It is recorded in
// backup manifests and release metadata, and printed by
// `opendeployctl version`, so restores and upgrades can refuse or stop
// before an incompatible downgrade.
const Version = 1
