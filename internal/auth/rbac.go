package auth

import "github.com/anreddykarthikreddy3003/opendeploy/internal/model"

// Action is an authorisable operation.
type Action string

// Project-scoped actions.
const (
	ProjectRead      Action = "project.read"
	ProjectSettings  Action = "project.settings"
	ProjectDelete    Action = "project.delete"
	ProjectTrust     Action = "project.trust"
	MembersManage    Action = "members.manage"
	DeployCreate     Action = "deploy.create"
	DeployRollback   Action = "deploy.rollback"
	DeployCancel     Action = "deploy.cancel"
	DeployPromote    Action = "deploy.promote"
	LogsRead         Action = "logs.read"
	PreviewManage    Action = "preview.manage"
	DomainsManage    Action = "domains.manage"
	SecretsList      Action = "secrets.list"
	SecretsWrite     Action = "secrets.write"
	SecretsReveal    Action = "secrets.reveal"
	VolumesManage    Action = "volumes.manage"
	CapabilityGrant  Action = "capability.grant"
	ProjectAuditRead Action = "project.audit.read"
)

// Node-scoped actions (owner only).
const (
	ProjectCreate Action = "project.create"
	UsersManage   Action = "users.manage"
	NodeSettings  Action = "node.settings"
	UpdateManage  Action = "update.manage"
	UpdateTrust   Action = "update.trust"
	BackupManage  Action = "backup.manage"
	BackupRestore Action = "backup.restore"
	AuditRead     Action = "audit.read"
	GitConnect    Action = "git.connect"
	RemoteAdmin   Action = "remote_admin.manage"
	SystemRead    Action = "system.read"
	// PrivilegedCreate creates a project in the Privileged/Unsafe class.
	PrivilegedCreate Action = "project.create_privileged"
)

var roleRank = map[string]int{model.RoleViewer: 1, model.RoleDeveloper: 2, model.RoleAdmin: 3, model.RoleOwner: 4}

// minProjectRole is the minimum project role for each project action.
var minProjectRole = map[Action]string{
	ProjectRead:      model.RoleViewer,
	LogsRead:         model.RoleViewer,
	SecretsList:      model.RoleDeveloper,
	DeployCreate:     model.RoleDeveloper,
	DeployRollback:   model.RoleDeveloper,
	DeployCancel:     model.RoleDeveloper,
	DeployPromote:    model.RoleDeveloper,
	PreviewManage:    model.RoleDeveloper,
	ProjectSettings:  model.RoleAdmin,
	ProjectDelete:    model.RoleAdmin,
	ProjectTrust:     model.RoleAdmin,
	MembersManage:    model.RoleAdmin,
	DomainsManage:    model.RoleAdmin,
	SecretsWrite:     model.RoleAdmin,
	SecretsReveal:    model.RoleAdmin,
	VolumesManage:    model.RoleAdmin,
	ProjectAuditRead: model.RoleAdmin,
	CapabilityGrant:  model.RoleOwner, // privileged capability: owner only
}

// nodeActions require the given global role.
var nodeActions = map[Action]string{
	ProjectCreate:    model.RoleAdmin,
	SystemRead:       model.RoleViewer,
	UsersManage:      model.RoleOwner,
	NodeSettings:     model.RoleOwner,
	UpdateManage:     model.RoleOwner,
	UpdateTrust:      model.RoleOwner,
	BackupManage:     model.RoleOwner,
	BackupRestore:    model.RoleOwner,
	AuditRead:        model.RoleOwner,
	GitConnect:       model.RoleOwner,
	RemoteAdmin:      model.RoleOwner,
	PrivilegedCreate: model.RoleOwner,
}

// Sensitive actions require recent re-authentication (and MFA in
// production mode) (PRD §15.2).
var sensitive = map[Action]bool{
	SecretsReveal:    true,
	CapabilityGrant:  true,
	UpdateTrust:      true,
	RemoteAdmin:      true,
	BackupRestore:    true,
	ProjectDelete:    true,
	UsersManage:      true,
	ProjectTrust:     true,
	GitConnect:       true,
	PrivilegedCreate: true,
}

// Sensitive reports whether action needs recent re-authentication.
func Sensitive(a Action) bool { return sensitive[a] }

// AllowedProject decides a project-scoped action. globalRole is the user's
// node role; projectRole is their membership role ("" if not a member).
// API tokens are further capped by capRole.
func AllowedProject(globalRole, projectRole, capRole string, a Action) bool {
	need, ok := minProjectRole[a]
	if !ok {
		return false
	}
	eff := projectRole
	if globalRole == model.RoleOwner {
		eff = model.RoleOwner
	}
	if eff == "" {
		return false
	}
	if capRole != "" && roleRank[capRole] < roleRank[eff] {
		eff = capRole
	}
	return roleRank[eff] >= roleRank[need]
}

// AllowedNode decides a node-scoped action.
func AllowedNode(globalRole, capRole string, a Action) bool {
	need, ok := nodeActions[a]
	if !ok {
		return false
	}
	eff := globalRole
	if capRole != "" && roleRank[capRole] < roleRank[eff] {
		eff = capRole
	}
	return roleRank[eff] >= roleRank[need]
}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := roleRank[r]; return ok }
