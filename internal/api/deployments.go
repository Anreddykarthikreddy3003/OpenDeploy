package api

import (
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// MaxUploadBytes bounds source archive uploads.
const MaxUploadBytes = 256 << 20

var shaRE = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)

// createDeployment creates a new generation and enqueues its job atomically.
func (s *Server) createDeployment(r *http.Request, proj *store.Project, env *store.Environment, trigger, branch, sha string) (*store.Deployment, error) {
	p := principal(r)
	var d *store.Deployment
	err := s.S.Tx(r.Context(), func(tx *sql.Tx) error {
		var err error
		d, err = store.CreateDeploymentTx(r.Context(), tx, store.NewDeployment{EnvironmentID: env.ID, Trigger: trigger, CommitSHA: sha,
			Branch: firstNonEmpty(branch, env.Branch, proj.ProductionBranch), CreatedBy: p.User.ID})
		if err != nil {
			return err
		}
		return platform.EnqueueDeployTx(r.Context(), tx, d.ID)
	})
	if err != nil {
		return nil, err
	}
	s.audit(r, "deployment.create", "deployment", d.ID, proj.ID, audit.Success, map[string]string{"generation": strconv.FormatInt(d.Generation, 10), "environment_id": env.ID})
	return d, nil
}

func (s *Server) projectEnv(r *http.Request, proj *store.Project, name string) (*store.Environment, error) {
	if name == "" {
		name = "production"
	}
	e, err := s.S.GetEnvironmentByName(r.Context(), proj.ID, name)
	if err != nil {
		if e2, err2 := s.S.GetEnvironment(r.Context(), name); err2 == nil && e2.ProjectID == proj.ID {
			return e2, nil
		}
		return nil, errf(404, "not_found", "environment not found")
	}
	return e, nil
}

func (s *Server) handleListDeployments(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectRead)
	if err != nil {
		return err
	}
	envID := ""
	if n := r.URL.Query().Get("environment"); n != "" {
		e, err := s.projectEnv(r, proj, n)
		if err != nil {
			return err
		}
		envID = e.ID
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ds, err := s.S.ListDeployments(r.Context(), proj.ID, envID, limit)
	if err != nil {
		return err
	}
	if ds == nil {
		ds = []*store.Deployment{}
	}
	writeJSON(w, 200, ds)
	return nil
}

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.DeployCreate)
	if err != nil {
		return err
	}
	var req struct {
		Environment string `json:"environment"`
		Branch      string `json:"branch"`
		SHA         string `json:"sha"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if proj.CloneURL == "" {
		return errf(400, "bad_request", "this project deploys uploaded sources; use the upload endpoint or `opendeployctl deploy`")
	}
	if req.SHA != "" && !shaRE.MatchString(req.SHA) {
		return errf(400, "bad_request", "sha must be a full commit hash")
	}
	env, err := s.projectEnv(r, proj, req.Environment)
	if err != nil {
		return err
	}
	if env.Kind == "preview" {
		return errf(400, "bad_request", "previews are driven by pull requests")
	}
	d, err := s.createDeployment(r, proj, env, "manual", req.Branch, req.SHA)
	if err != nil {
		return err
	}
	writeJSON(w, 202, d)
	return nil
}

// handleUpload accepts a gzip'd tar of the project source (CLI deploys and
// projects without Git).
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.DeployCreate)
	if err != nil {
		return err
	}
	env, err := s.projectEnv(r, proj, r.URL.Query().Get("environment"))
	if err != nil {
		return err
	}
	if env.Kind == "preview" {
		return errf(400, "bad_request", "cannot upload to a preview environment")
	}
	body := http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	tmp, err := os.CreateTemp(s.sourcesDir(), "upload-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, body)
	tmp.Close()
	if err != nil {
		return errf(413, "too_large", "upload failed or exceeds %d MiB", MaxUploadBytes>>20)
	}
	if err := checkGzip(tmp.Name()); err != nil {
		return errf(400, "bad_request", "upload must be a .tar.gz archive")
	}
	p := principal(r)
	var d *store.Deployment
	err = s.S.Tx(r.Context(), func(tx *sql.Tx) error {
		var err error
		d, err = store.CreateDeploymentTx(r.Context(), tx, store.NewDeployment{EnvironmentID: env.ID, Trigger: "manual", CreatedBy: p.User.ID,
			CommitMessage: "uploaded source (" + strconv.FormatInt(n>>10, 10) + " KiB)"})
		if err != nil {
			return err
		}
		sha := "archive-" + d.ID
		if _, err := tx.ExecContext(r.Context(), `UPDATE deployments SET commit_sha=? WHERE id=?`, sha, d.ID); err != nil {
			return err
		}
		if err := os.Rename(tmp.Name(), filepath.Join(s.sourcesDir(), d.ID+".tar.gz")); err != nil {
			return err
		}
		return platform.EnqueueDeployTx(r.Context(), tx, d.ID)
	})
	if err != nil {
		return err
	}
	s.audit(r, "deployment.create", "deployment", d.ID, proj.ID, audit.Success, map[string]string{"reason": "source upload", "generation": strconv.FormatInt(d.Generation, 10)})
	writeJSON(w, 202, d)
	return nil
}

func (s *Server) sourcesDir() string {
	d := filepath.Join(s.P.Node.DataDir, "sources")
	_ = os.MkdirAll(d, 0o750)
	return d
}

func checkGzip(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = gzip.NewReader(f)
	return err
}

// deploymentFor loads a deployment and authorises action on its project.
func (s *Server) deploymentFor(r *http.Request, a auth.Action) (*store.Deployment, *store.Project, error) {
	d, err := s.S.GetDeployment(r.Context(), r.PathValue("id"))
	if err != nil {
		return nil, nil, errNotFound
	}
	proj, err := s.requireProject(r, d.ProjectID, a)
	if err != nil {
		return nil, nil, err
	}
	return d, proj, nil
}

func (s *Server) handleGetDeployment(w http.ResponseWriter, r *http.Request) error {
	d, proj, err := s.deploymentFor(r, auth.ProjectRead)
	if err != nil {
		return err
	}
	ctx := r.Context()
	events, _ := s.S.DeploymentEvents(ctx, d.ID)
	ws, _ := s.S.WorkloadsForDeployment(ctx, d.ID)
	env, _ := s.S.GetEnvironment(ctx, d.EnvironmentID)
	var art *store.Artifact
	if d.ArtifactID != "" {
		art, _ = s.S.GetArtifact(ctx, d.ArtifactID)
	}
	url := ""
	if env != nil && env.GeneratedHostname != "" {
		url = s.P.PublicURL(env.GeneratedHostname)
	}
	writeJSON(w, 200, map[string]any{"deployment": d, "project": proj, "environment": env, "events": events, "workloads": ws, "artifact": art,
		"url": url, "is_current": env != nil && env.CurrentDeploymentID == d.ID})
	return nil
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) error {
	d, _, err := s.deploymentFor(r, auth.LogsRead)
	if err != nil {
		return err
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	lines, err := s.S.Logs(r.Context(), d.ID, after, 2000)
	if err != nil {
		return err
	}
	if lines == nil {
		lines = []store.LogLine{}
	}
	writeJSON(w, 200, lines)
	return nil
}

// handleEvents streams deployment status and log lines (SSE).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) error {
	d, _, err := s.deploymentFor(r, auth.LogsRead)
	if err != nil {
		return err
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		return errf(500, "internal", "streaming unsupported")
	}
	ch, unsub := s.P.Events.Subscribe("deployment:" + d.ID)
	defer unsub()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	send := func(ev string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev, b)
		fl.Flush()
	}
	// Backfill persisted lines first.
	for {
		lines, err := s.S.Logs(r.Context(), d.ID, after, 2000)
		if err != nil || len(lines) == 0 {
			break
		}
		for _, l := range lines {
			send("log", l)
			after = l.ID
		}
	}
	cur, _ := s.S.GetDeployment(r.Context(), d.ID)
	if cur != nil {
		send("status", map[string]string{"to": string(cur.Status)})
		if cur.Status.Terminal() {
			return nil
		}
	}
	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return nil
		case <-hb.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		case e := <-ch:
			if e.Type == "log" {
				// Re-read from the DB so clients receive stable IDs.
				lines, _ := s.S.Logs(r.Context(), d.ID, after, 2000)
				for _, l := range lines {
					send("log", l)
					after = l.ID
				}
				continue
			}
			send(e.Type, e.Data)
			if m, ok := e.Data.(map[string]string); ok {
				if st := model.DeploymentStatus(m["to"]); st.Terminal() {
					return nil
				}
			}
		}
	}
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) error {
	d, proj, err := s.deploymentFor(r, auth.DeployCancel)
	if err != nil {
		return err
	}
	if !model.CanTransition(d.Status, model.StatusCancelled) || d.Status == model.StatusRouterSwitched || d.Status == model.StatusCommittingPointer || d.Status == model.StatusDrainingOld || d.Status == model.StatusPromotionIntent {
		return errf(409, "conflict", "deployment can no longer be cancelled (%s)", d.Status)
	}
	_ = s.P.Builder.Cancel(r.Context(), d.ID)
	if err := s.S.Transition(r.Context(), d.ID, d.Status, model.StatusCancelled, "cancelled by user"); err != nil {
		return err
	}
	go s.P.CleanupCandidate(d.ID)
	s.audit(r, "deployment.cancel", "deployment", d.ID, proj.ID, audit.Success, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handlePromote(w http.ResponseWriter, r *http.Request) error {
	d, proj, err := s.deploymentFor(r, auth.DeployPromote)
	if err != nil {
		return err
	}
	if d.Status != model.StatusReady {
		return errf(409, "conflict", "only READY deployments can be promoted manually")
	}
	if _, err := s.S.Enqueue(r.Context(), platform.JobPromote, "promote:"+d.ID, map[string]string{"deployment_id": d.ID}, 5); err != nil {
		return err
	}
	s.audit(r, "deployment.promote_request", "deployment", d.ID, proj.ID, audit.Success, nil)
	writeJSON(w, 202, map[string]bool{"ok": true})
	return nil
}

// handleRollback creates a new desired generation that re-runs a retained
// immutable artifact (no GitHub, no rebuild; PRD §11.4).
func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) error {
	trigger := "rollback"
	action := auth.DeployRollback
	if r.URL.Path[len(r.URL.Path)-len("redeploy"):] == "redeploy" {
		trigger, action = "redeploy", auth.DeployCreate
	}
	src, proj, err := s.deploymentFor(r, action)
	if err != nil {
		return err
	}
	if src.ArtifactID == "" || (src.Status != model.StatusSucceeded && src.Status != model.StatusReady) {
		return errf(409, "conflict", "only successful deployments with a retained artifact can be re-run")
	}
	p := principal(r)
	var d *store.Deployment
	err = s.S.Tx(r.Context(), func(tx *sql.Tx) error {
		var err error
		d, err = store.CreateDeploymentTx(r.Context(), tx, store.NewDeployment{EnvironmentID: src.EnvironmentID, Trigger: trigger, CommitSHA: src.CommitSHA,
			CommitMessage: src.CommitMessage, CommitAuthor: src.CommitAuthor, Branch: src.Branch, RollbackOf: src.ID, ArtifactID: src.ArtifactID, CreatedBy: p.User.ID})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(r.Context(), `UPDATE deployments SET config_snapshot=?, build_inputs=?, build_strategy=?, trust_class=?, runtime_class=? WHERE id=?`,
			string(src.ConfigSnapshot), string(src.BuildInputs), src.BuildStrategy, src.TrustClass, src.RuntimeClass, d.ID); err != nil {
			return err
		}
		return platform.EnqueueDeployTx(r.Context(), tx, d.ID)
	})
	if err != nil {
		return err
	}
	s.audit(r, "deployment."+trigger, "deployment", d.ID, proj.ID, audit.Success, map[string]string{"from": src.ID, "generation": strconv.FormatInt(d.Generation, 10)})
	writeJSON(w, 202, d)
	return nil
}

func (s *Server) handleRuntimeLogs(w http.ResponseWriter, r *http.Request) error {
	env, err := s.S.GetEnvironment(r.Context(), r.PathValue("env"))
	if err != nil {
		return errNotFound
	}
	if _, err := s.requireProject(r, env.ProjectID, auth.LogsRead); err != nil {
		return err
	}
	if env.CurrentDeploymentID == "" {
		writeJSON(w, 200, []any{})
		return nil
	}
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	ws, err := s.S.WorkloadsForDeployment(r.Context(), env.CurrentDeploymentID)
	if err != nil {
		return err
	}
	type line struct {
		Workload string `json:"workload"`
		Replica  int    `json:"replica"`
		Time     string `json:"time"`
		Stream   string `json:"stream"`
		Text     string `json:"text"`
	}
	out := []line{}
	for _, wk := range ws {
		lines, err := s.P.Runtime.Logs(r.Context(), wk.ID, tail, time.Time{})
		if err != nil {
			continue
		}
		for _, l := range lines {
			out = append(out, line{Workload: wk.ID, Replica: wk.Replica, Time: l.Time, Stream: l.Stream, Text: l.Text})
		}
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20+1))
	if err != nil || len(body) > 5<<20 {
		writeJSON(w, 413, errf(413, "too_large", "payload too large"))
		return
	}
	res := s.P.HandleGitHubWebhook(r.Context(), r.Header.Get("X-GitHub-Event"), r.Header.Get("X-GitHub-Delivery"),
		r.Header.Get("X-Hub-Signature-256"), s.clientIP(r), body)
	writeJSON(w, res.Status, res)
}
