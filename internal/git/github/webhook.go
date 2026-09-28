package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxWebhookBody bounds accepted webhook payloads (GitHub caps at 25 MB;
// OpenDeploy only needs push/PR metadata).
const MaxWebhookBody = 5 << 20

var (
	ErrMissingSignature = errors.New("missing X-Hub-Signature-256")
	ErrBadSignature     = errors.New("invalid webhook signature")
	deliveryRE          = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)
	shaRE               = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// VerifySignature checks X-Hub-Signature-256 over the RAW body using
// HMAC-SHA256 and a constant-time comparison (PRD §6.2 step 2, [R2]). It
// must be called before any parsing.
func VerifySignature(secret, body []byte, header string) error {
	if header == "" {
		return ErrMissingSignature
	}
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return ErrBadSignature
	}
	got, err := hex.DecodeString(header[len(prefix):])
	if err != nil || len(got) != sha256.Size {
		return ErrBadSignature
	}
	if len(secret) == 0 {
		return ErrBadSignature
	}
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	if !hmac.Equal(got, m.Sum(nil)) {
		return ErrBadSignature
	}
	return nil
}

// Sign computes the header value for body (tests and fixtures).
func Sign(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// ValidDeliveryID checks the X-GitHub-Delivery format.
func ValidDeliveryID(s string) bool { return deliveryRE.MatchString(s) }

// ValidSHA checks a full commit SHA (SHA-1 or SHA-256 repositories).
func ValidSHA(s string) bool { return shaRE.MatchString(s) }

type RepoRef struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
	Private  bool   `json:"private"`
	Fork     bool   `json:"fork"`
}

type InstallationRef struct {
	ID int64 `json:"id"`
}

type Commit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	Author  struct {
		Name     string `json:"name"`
		Username string `json:"username"`
	} `json:"author"`
}

// PushEvent is the subset of the push payload OpenDeploy uses.
type PushEvent struct {
	Ref          string          `json:"ref"`
	Before       string          `json:"before"`
	After        string          `json:"after"`
	Created      bool            `json:"created"`
	Deleted      bool            `json:"deleted"`
	Forced       bool            `json:"forced"`
	Repository   RepoRef         `json:"repository"`
	Installation InstallationRef `json:"installation"`
	HeadCommit   *Commit         `json:"head_commit"`
	Sender       struct {
		Login string `json:"login"`
	} `json:"sender"`
}

// Branch returns the branch name for refs/heads/* refs.
func (p *PushEvent) Branch() (string, bool) {
	if !strings.HasPrefix(p.Ref, "refs/heads/") {
		return "", false
	}
	return strings.TrimPrefix(p.Ref, "refs/heads/"), true
}

type PRSide struct {
	Ref  string  `json:"ref"`
	SHA  string  `json:"sha"`
	Repo RepoRef `json:"repo"`
}

// PullRequestEvent is the subset of the pull_request payload.
type PullRequestEvent struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Number int    `json:"number"`
		State  string `json:"state"`
		Title  string `json:"title"`
		Merged bool   `json:"merged"`
		Head   PRSide `json:"head"`
		Base   PRSide `json:"base"`
		User   struct {
			Login string `json:"login"`
		} `json:"user"`
		AuthorAssociation string `json:"author_association"`
	} `json:"pull_request"`
	Repository   RepoRef         `json:"repository"`
	Installation InstallationRef `json:"installation"`
}

// FromFork reports whether the PR head lives in a different repository.
func (p *PullRequestEvent) FromFork() bool {
	return p.PullRequest.Head.Repo.ID == 0 || p.PullRequest.Head.Repo.ID != p.PullRequest.Base.Repo.ID
}

// InstallationEvent covers installation and installation_repositories.
type InstallationEvent struct {
	Action       string `json:"action"`
	Installation struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
	} `json:"installation"`
	Repositories        []RepoRef `json:"repositories"`
	RepositoriesAdded   []RepoRef `json:"repositories_added"`
	RepositoriesRemoved []RepoRef `json:"repositories_removed"`
}

// Event is a parsed, verified webhook.
type Event struct {
	Name         string
	DeliveryID   string
	Push         *PushEvent
	PullRequest  *PullRequestEvent
	Installation *InstallationEvent
}

// InstallationID returns the installation the event belongs to.
func (e *Event) InstallationID() int64 {
	switch {
	case e.Push != nil:
		return e.Push.Installation.ID
	case e.PullRequest != nil:
		return e.PullRequest.Installation.ID
	case e.Installation != nil:
		return e.Installation.Installation.ID
	}
	return 0
}

// RepositoryID returns the repository the event belongs to.
func (e *Event) RepositoryID() int64 {
	switch {
	case e.Push != nil:
		return e.Push.Repository.ID
	case e.PullRequest != nil:
		return e.PullRequest.Repository.ID
	}
	return 0
}

// SupportedEvents are the event types OpenDeploy parses; others are
// acknowledged and ignored.
var SupportedEvents = map[string]bool{"push": true, "pull_request": true, "installation": true, "installation_repositories": true, "ping": true}

// ParseEvent parses a verified webhook body.
func ParseEvent(name, delivery string, body []byte) (*Event, error) {
	if !ValidDeliveryID(delivery) {
		return nil, fmt.Errorf("invalid delivery id")
	}
	ev := &Event{Name: name, DeliveryID: delivery}
	switch name {
	case "push":
		var p PushEvent
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, err
		}
		if !p.Deleted && !ValidSHA(p.After) {
			return nil, fmt.Errorf("push: invalid after sha")
		}
		if p.Repository.ID == 0 || p.Installation.ID == 0 {
			return nil, fmt.Errorf("push: missing repository or installation")
		}
		ev.Push = &p
	case "pull_request":
		var p PullRequestEvent
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, err
		}
		if p.Repository.ID == 0 || p.Installation.ID == 0 || p.Number <= 0 {
			return nil, fmt.Errorf("pull_request: missing fields")
		}
		if p.Action != "closed" && !ValidSHA(p.PullRequest.Head.SHA) {
			return nil, fmt.Errorf("pull_request: invalid head sha")
		}
		ev.PullRequest = &p
	case "installation", "installation_repositories":
		var p InstallationEvent
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, err
		}
		ev.Installation = &p
	case "ping":
	default:
		return nil, fmt.Errorf("unsupported event %q", name)
	}
	return ev, nil
}
