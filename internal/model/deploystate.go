// Package model holds small shared domain types with no dependencies.
package model

// DeploymentStatus is a durable deployment state (PRD §11.1).
type DeploymentStatus string

const (
	StatusReceived          DeploymentStatus = "RECEIVED"
	StatusValidating        DeploymentStatus = "VALIDATING"
	StatusFetching          DeploymentStatus = "FETCHING"
	StatusDetecting         DeploymentStatus = "DETECTING"
	StatusBuilding          DeploymentStatus = "BUILDING"
	StatusArtifactReady     DeploymentStatus = "ARTIFACT_READY"
	StatusStartingCandidate DeploymentStatus = "STARTING_CANDIDATE"
	StatusHealthChecking    DeploymentStatus = "HEALTH_CHECKING"
	StatusPromotionIntent   DeploymentStatus = "PROMOTION_INTENT"
	StatusRouterSwitched    DeploymentStatus = "ROUTER_SWITCHED"
	StatusCommittingPointer DeploymentStatus = "COMMITTING_POINTER"
	StatusDrainingOld       DeploymentStatus = "DRAINING_OLD"
	StatusSucceeded         DeploymentStatus = "SUCCEEDED"
	StatusFailed            DeploymentStatus = "FAILED"
	StatusSuperseded        DeploymentStatus = "SUPERSEDED"
	StatusCancelled         DeploymentStatus = "CANCELLED"
	// StatusReady is a terminal state for a healthy candidate that was not
	// auto-promoted (auto_promote: false); it can be promoted manually.
	StatusReady DeploymentStatus = "READY"
)

// Pipeline is the forward order of non-terminal states.
var Pipeline = []DeploymentStatus{
	StatusReceived, StatusValidating, StatusFetching, StatusDetecting, StatusBuilding, StatusArtifactReady,
	StatusStartingCandidate, StatusHealthChecking, StatusPromotionIntent, StatusRouterSwitched,
	StatusCommittingPointer, StatusDrainingOld, StatusSucceeded,
}

// Terminal reports whether s is final.
func (s DeploymentStatus) Terminal() bool {
	switch s {
	case StatusSucceeded, StatusFailed, StatusSuperseded, StatusCancelled:
		return true
	}
	return false
}

func index(s DeploymentStatus) int {
	for i, p := range Pipeline {
		if p == s {
			return i
		}
	}
	return -1
}

// CanTransition reports whether from -> to is a legal transition.
//
// Rules: forward-only along the pipeline (skips allowed, e.g. rollback jumps
// from RECEIVED to STARTING_CANDIDATE because the artifact already exists);
// any non-terminal state may move to FAILED or CANCELLED; any state before
// ROUTER_SWITCHED may become SUPERSEDED (after the router switch the
// deployment is live and must be completed or restored, never superseded).
// HEALTH_CHECKING may end at READY; READY may resume at PROMOTION_INTENT or
// be superseded/cancelled.
func CanTransition(from, to DeploymentStatus) bool {
	if from.Terminal() {
		return false
	}
	if from == StatusReady {
		return to == StatusPromotionIntent || to == StatusSuperseded || to == StatusCancelled || to == StatusFailed
	}
	switch to {
	case StatusFailed, StatusCancelled:
		return true
	case StatusSuperseded:
		return index(from) < index(StatusRouterSwitched)
	case StatusReady:
		return from == StatusHealthChecking
	}
	fi, ti := index(from), index(to)
	return fi >= 0 && ti > fi
}

// Valid reports whether s is a known status.
func (s DeploymentStatus) Valid() bool {
	return index(s) >= 0 || s == StatusFailed || s == StatusSuperseded || s == StatusCancelled || s == StatusReady
}

// Roles (PRD §15.2).
const (
	RoleOwner     = "owner"
	RoleAdmin     = "admin" // Project Admin
	RoleDeveloper = "developer"
	RoleViewer    = "viewer"
)
