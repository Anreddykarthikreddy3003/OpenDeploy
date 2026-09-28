package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

type Project struct {
	ID                  string         `json:"id"`
	Name                string         `json:"name"`
	GitConnectionID     string         `json:"git_connection_id,omitempty"`
	RepoID              int64          `json:"repo_id"`
	RepoFullName        string         `json:"repo_full_name"`
	CloneURL            string         `json:"clone_url"`
	RootDir             string         `json:"root_dir"`
	ProductionBranch    string         `json:"production_branch"`
	TrustClass          string         `json:"trust_class"`
	PreferGVisor        bool           `json:"prefer_gvisor"`
	AllowPublicForks    bool           `json:"allow_public_forks"`
	PreviewsEnabled     bool           `json:"previews_enabled"`
	AutoDeploy          bool           `json:"auto_deploy"`
	GrantedCapabilities []string       `json:"granted_capabilities"`
	ConfigOverride      string         `json:"config_override,omitempty"`
	BuildOverrides      BuildOverrides `json:"build_overrides"`
	CreatedAt           string         `json:"created_at"`
	UpdatedAt           string         `json:"updated_at"`
}

// BuildOverrides are administrator-set build/start settings used by the
// manual wizard (detection priority 7) or to override inference.
type BuildOverrides struct {
	Strategy     string            `json:"strategy,omitempty"`
	BuildCommand string            `json:"build_command,omitempty"`
	StartCommand string            `json:"start_command,omitempty"`
	OutputDir    string            `json:"output_dir,omitempty"`
	Port         int               `json:"port,omitempty"`
	Env          map[string]string `json:"env,omitempty"` // non-secret build args
}

const projectCols = `id,name,COALESCE(git_connection_id,''),repo_id,repo_full_name,clone_url,root_dir,production_branch,trust_class,
prefer_gvisor,allow_public_forks,previews_enabled,auto_deploy,granted_capabilities,config_override,build_overrides,created_at,updated_at`

func scanProject(r interface{ Scan(...any) error }) (*Project, error) {
	var p Project
	var caps, bo string
	err := r.Scan(&p.ID, &p.Name, &p.GitConnectionID, &p.RepoID, &p.RepoFullName, &p.CloneURL, &p.RootDir, &p.ProductionBranch,
		&p.TrustClass, &p.PreferGVisor, &p.AllowPublicForks, &p.PreviewsEnabled, &p.AutoDeploy, &caps, &p.ConfigOverride, &bo, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	_ = json.Unmarshal([]byte(caps), &p.GrantedCapabilities)
	if p.GrantedCapabilities == nil {
		p.GrantedCapabilities = []string{}
	}
	_ = json.Unmarshal([]byte(bo), &p.BuildOverrides)
	return &p, nil
}

// CreateProject inserts a project plus its production environment.
func (s *Store) CreateProject(ctx context.Context, p *Project) error {
	if p.ID == "" {
		p.ID = ids.New("prj")
	}
	now := state.Now()
	p.CreatedAt, p.UpdatedAt = now, now
	if p.RootDir == "" {
		p.RootDir = "."
	}
	if p.ProductionBranch == "" {
		p.ProductionBranch = "main"
	}
	if p.TrustClass == "" {
		p.TrustClass = "trusted"
	}
	if p.GrantedCapabilities == nil {
		p.GrantedCapabilities = []string{}
	}
	caps, _ := json.Marshal(p.GrantedCapabilities)
	bo, _ := json.Marshal(p.BuildOverrides)
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var gc any
		if p.GitConnectionID != "" {
			gc = p.GitConnectionID
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO projects(id,name,git_connection_id,repo_id,repo_full_name,clone_url,root_dir,production_branch,
			trust_class,prefer_gvisor,allow_public_forks,previews_enabled,auto_deploy,granted_capabilities,config_override,build_overrides,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p.ID, p.Name, gc, p.RepoID, p.RepoFullName, p.CloneURL, p.RootDir, p.ProductionBranch, p.TrustClass,
			b2i(p.PreferGVisor), b2i(p.AllowPublicForks), b2i(p.PreviewsEnabled), b2i(p.AutoDeploy), string(caps), p.ConfigOverride, string(bo), now, now)
		if err != nil {
			if isUnique(err) {
				return ErrConflict
			}
			return err
		}
		_, err = insertEnvironment(ctx, tx, &Environment{ProjectID: p.ID, Name: "production", Kind: "production", Branch: p.ProductionBranch})
		return err
	})
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func (s *Store) GetProject(ctx context.Context, id string) (*Project, error) {
	return scanProject(s.DB.R().QueryRowContext(ctx, `SELECT `+projectCols+` FROM projects WHERE id=? AND deleted_at=''`, id))
}

func (s *Store) GetProjectByName(ctx context.Context, name string) (*Project, error) {
	return scanProject(s.DB.R().QueryRowContext(ctx, `SELECT `+projectCols+` FROM projects WHERE name=? AND deleted_at=''`, name))
}

// ProjectsByRepo returns live projects bound to a repository ID.
func (s *Store) ProjectsByRepo(ctx context.Context, repoID int64) ([]*Project, error) {
	return s.queryProjects(ctx, `SELECT `+projectCols+` FROM projects WHERE repo_id=? AND deleted_at='' ORDER BY name`, repoID)
}

func (s *Store) ListProjects(ctx context.Context) ([]*Project, error) {
	return s.queryProjects(ctx, `SELECT `+projectCols+` FROM projects WHERE deleted_at='' ORDER BY name`)
}

// ListProjectsForUser returns projects the user is a member of.
func (s *Store) ListProjectsForUser(ctx context.Context, userID string) ([]*Project, error) {
	return s.queryProjects(ctx, `SELECT `+projectCols+` FROM projects WHERE deleted_at='' AND id IN
		(SELECT project_id FROM project_members WHERE user_id=?) ORDER BY name`, userID)
}

func (s *Store) queryProjects(ctx context.Context, q string, args ...any) ([]*Project, error) {
	rows, err := s.DB.R().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProjectUpdate lists mutable project fields; nil means unchanged.
type ProjectUpdate struct {
	ProductionBranch    *string
	RootDir             *string
	TrustClass          *string
	PreferGVisor        *bool
	AllowPublicForks    *bool
	PreviewsEnabled     *bool
	AutoDeploy          *bool
	GrantedCapabilities *[]string
	ConfigOverride      *string
	BuildOverrides      *BuildOverrides
}

func (s *Store) UpdateProject(ctx context.Context, id string, u ProjectUpdate) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		sets := []string{"updated_at=?"}
		args := []any{state.Now()}
		add := func(col string, v any) { sets = append(sets, col+"=?"); args = append(args, v) }
		if u.ProductionBranch != nil {
			add("production_branch", *u.ProductionBranch)
			if _, err := tx.ExecContext(ctx, `UPDATE environments SET branch=?, updated_at=? WHERE project_id=? AND kind='production'`,
				*u.ProductionBranch, state.Now(), id); err != nil {
				return err
			}
		}
		if u.RootDir != nil {
			add("root_dir", *u.RootDir)
		}
		if u.TrustClass != nil {
			add("trust_class", *u.TrustClass)
		}
		if u.PreferGVisor != nil {
			add("prefer_gvisor", b2i(*u.PreferGVisor))
		}
		if u.AllowPublicForks != nil {
			add("allow_public_forks", b2i(*u.AllowPublicForks))
		}
		if u.PreviewsEnabled != nil {
			add("previews_enabled", b2i(*u.PreviewsEnabled))
		}
		if u.AutoDeploy != nil {
			add("auto_deploy", b2i(*u.AutoDeploy))
		}
		if u.GrantedCapabilities != nil {
			b, _ := json.Marshal(*u.GrantedCapabilities)
			add("granted_capabilities", string(b))
		}
		if u.ConfigOverride != nil {
			add("config_override", *u.ConfigOverride)
		}
		if u.BuildOverrides != nil {
			b, _ := json.Marshal(*u.BuildOverrides)
			add("build_overrides", string(b))
		}
		args = append(args, id)
		res, err := tx.ExecContext(ctx, `UPDATE projects SET `+strings.Join(sets, ",")+` WHERE id=? AND deleted_at=''`, args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SoftDeleteProject marks a project deleted; the name is released by
// suffixing so it can be reused, and environments are marked deleting.
func (s *Store) SoftDeleteProject(ctx context.Context, id string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := state.Now()
		res, err := tx.ExecContext(ctx, `UPDATE projects SET deleted_at=?, name=name||'~deleted~'||id, updated_at=? WHERE id=? AND deleted_at=''`, now, now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, `UPDATE environments SET status='deleting', updated_at=? WHERE project_id=?`, now, id)
		return err
	})
}

// Members

func (s *Store) SetMember(ctx context.Context, projectID, userID, role string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO project_members(project_id,user_id,role) VALUES(?,?,?)
			ON CONFLICT(project_id,user_id) DO UPDATE SET role=excluded.role`, projectID, userID, role)
		return err
	})
}

func (s *Store) RemoveMember(ctx context.Context, projectID, userID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM project_members WHERE project_id=? AND user_id=?`, projectID, userID)
		return err
	})
}

// MemberRole returns the user's project role or "" when not a member.
func (s *Store) MemberRole(ctx context.Context, projectID, userID string) (string, error) {
	var r string
	err := s.DB.R().QueryRowContext(ctx, `SELECT role FROM project_members WHERE project_id=? AND user_id=?`, projectID, userID).Scan(&r)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return r, err
}

type Member struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Role   string `json:"role"`
}

func (s *Store) ListMembers(ctx context.Context, projectID string) ([]Member, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT u.id,u.email,u.name,m.role FROM project_members m JOIN users u ON u.id=m.user_id
		WHERE m.project_id=? ORDER BY u.email`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.Name, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
