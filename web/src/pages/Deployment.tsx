import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { errorMessage, get, post } from "../api/client";
import { TERMINAL_STATUSES, type Deployment, type DeploymentDetail, type LogLine, type RuntimeLogLine } from "../api/types";
import { Alert, Badge, Button, Card, Code, Loading, StatusBadge, Tabs, cx, useToast } from "../components/ui";
import { bytes, duration, formatDate, shortSha, timeAgo } from "../lib/format";

export function LogView({ lines, follow = true, empty = "No output yet." }: { lines: { key: string | number; text: string; stream?: string; at?: string }[]; follow?: boolean; empty?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [stick, setStick] = useState(true);
  useEffect(() => {
    if (follow && stick && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines, follow, stick]);
  return (
    <div
      ref={ref}
      onScroll={(e) => {
        const el = e.currentTarget;
        setStick(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
      }}
      className="scrollbar-thin h-[28rem] overflow-auto rounded-md border border-zinc-800 bg-black/60 p-3 font-mono text-xs leading-5"
    >
      {lines.length === 0 && <p className="text-zinc-500">{empty}</p>}
      {lines.map((l) => (
        <div key={l.key} className={cx("whitespace-pre-wrap break-all", l.stream === "stderr" ? "text-amber-200" : l.stream === "system" ? "text-sky-300" : "text-zinc-300")}>
          {l.text}
        </div>
      ))}
    </div>
  );
}

function useBuildLogs(id: string, onStatus: () => void) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [live, setLive] = useState(false);
  useEffect(() => {
    setLines([]);
    const es = new EventSource(`/api/v2/deployments/${id}/events`);
    setLive(true);
    const seen = new Set<number>();
    es.addEventListener("log", (e) => {
      const l = JSON.parse((e as MessageEvent).data) as LogLine;
      if (seen.has(l.id)) return;
      seen.add(l.id);
      setLines((xs) => (xs.length > 20000 ? [...xs.slice(-15000), l] : [...xs, l]));
    });
    es.addEventListener("status", (e) => {
      onStatus();
      const d = JSON.parse((e as MessageEvent).data);
      if (TERMINAL_STATUSES.includes(d.to)) {
        es.close();
        setLive(false);
      }
    });
    es.onerror = () => {
      // The server closes the stream when the deployment finishes.
      es.close();
      setLive(false);
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  return { lines, live };
}

export function DeploymentPage() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const nav = useNavigate();
  const toast = useToast();
  const [tab, setTab] = useState<"build" | "runtime" | "details">("build");
  const q = useQuery({
    queryKey: ["deployment", id],
    queryFn: () => get<DeploymentDetail>(`/api/v2/deployments/${id}`),
    refetchInterval: (query) => (query.state.data && TERMINAL_STATUSES.includes(query.state.data.deployment.status) ? false : 3000),
  });
  const { lines, live } = useBuildLogs(id, () => qc.invalidateQueries({ queryKey: ["deployment", id] }));
  const [busy, setBusy] = useState("");

  if (q.isLoading) return <Loading />;
  if (q.error) return <Alert>{errorMessage(q.error)}</Alert>;
  const { deployment: d, project, environment, events, workloads, artifact, url, is_current } = q.data!;
  const terminal = TERMINAL_STATUSES.includes(d.status);

  const act = async (name: string, fn: () => Promise<any>) => {
    setBusy(name);
    try {
      const r = await fn();
      if (r && (r as Deployment).id && (r as Deployment).id !== d.id) nav(`/deployments/${(r as Deployment).id}`);
      else await qc.invalidateQueries({ queryKey: ["deployment", id] });
      toast("green", `${name} requested`);
    } catch (e) {
      toast("red", errorMessage(e));
    } finally {
      setBusy("");
    }
  };

  return (
    <>
      <div className="mb-6">
        <Link to={`/projects/${project.id}`} className="text-sm text-zinc-400 hover:text-white">
          ← {project.name}
        </Link>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <h1 className="truncate text-xl font-semibold text-white">{d.commit_message ? d.commit_message.split("\n")[0] : `Deployment #${d.generation}`}</h1>
              <StatusBadge status={d.status} />
              {is_current && <Badge tone="green">current</Badge>}
            </div>
            <p className="mt-1 text-sm text-zinc-400">
              {environment?.name} · generation {d.generation} · {d.trigger}
              {d.commit_sha && !d.commit_sha.startsWith("archive-") && (
                <>
                  {" "}
                  · <Code>{shortSha(d.commit_sha)}</Code>
                  {d.branch && ` on ${d.branch}`}
                </>
              )}{" "}
              · {timeAgo(d.created_at)}
              {d.started_at && ` · ${duration(d.started_at, d.finished_at)}`}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {url && d.status === "SUCCEEDED" && is_current && (
              <a href={url} target="_blank" rel="noreferrer noopener">
                <Button>Visit</Button>
              </a>
            )}
            {!terminal && (
              <Button variant="danger" loading={busy === "Cancel"} onClick={() => act("Cancel", () => post(`/api/v2/deployments/${d.id}/cancel`))}>
                Cancel
              </Button>
            )}
            {d.status === "READY" && (
              <Button variant="primary" loading={busy === "Promote"} onClick={() => act("Promote", () => post(`/api/v2/deployments/${d.id}/promote`))}>
                Promote
              </Button>
            )}
            {terminal && d.artifact_id && !is_current && d.status !== "FAILED" && (
              <Button loading={busy === "Rollback"} onClick={() => act("Rollback", () => post(`/api/v2/deployments/${d.id}/rollback`))}>
                Roll back to this
              </Button>
            )}
            {terminal && (
              <Button loading={busy === "Redeploy"} onClick={() => act("Redeploy", () => post(`/api/v2/deployments/${d.id}/redeploy`))}>
                Redeploy
              </Button>
            )}
          </div>
        </div>
      </div>

      {d.error && (
        <div className="mb-4">
          <Alert title="Deployment failed">{d.error}</Alert>
        </div>
      )}

      <Tabs
        tabs={[
          { id: "build", label: `Build log${live ? " ●" : ""}` },
          { id: "runtime", label: "Runtime logs" },
          { id: "details", label: "Details" },
        ]}
        value={tab}
        onChange={setTab}
      />
      {tab === "build" && <LogView lines={lines.map((l) => ({ key: l.id, text: l.line, stream: l.stream }))} empty={terminal ? "No build output was recorded." : "Waiting for output…"} />}
      {tab === "runtime" && environment && <RuntimeLogs envId={environment.id} deploymentId={d.id} />}
      {tab === "details" && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Timeline">
            <ol className="space-y-2 text-sm">
              {(events ?? []).map((e) => (
                <li key={e.id} className="flex gap-3">
                  <span className="w-40 shrink-0 text-xs text-zinc-500">{formatDate(e.at)}</span>
                  <span>
                    <StatusBadge status={e.to} /> {e.message && <span className="ml-1 text-zinc-400">{e.message}</span>}
                  </span>
                </li>
              ))}
            </ol>
          </Card>
          <Card title="Isolation decision">
            <div className="mb-3 flex gap-2">
              <Badge tone={d.trust_class === "trusted" ? "green" : d.trust_class === "untrusted" ? "amber" : "red"}>{d.trust_class}</Badge>
              <Badge>runtime: {d.runtime_class || "—"}</Badge>
              {d.build_strategy && <Badge>build: {d.build_strategy}</Badge>}
            </div>
            <ul className="list-inside list-disc space-y-1 text-xs text-zinc-400">
              {(d.decision_reasons ?? []).map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </Card>
          {artifact && (
            <Card title="Artifact">
              <dl className="space-y-1 text-xs">
                <div>
                  <dt className="text-zinc-500">Digest</dt>
                  <dd className="break-all font-mono text-zinc-300">{artifact.digest}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Kind / size</dt>
                  <dd className="text-zinc-300">
                    {artifact.kind} · {bytes(artifact.size_bytes)}
                  </dd>
                </div>
              </dl>
            </Card>
          )}
          <Card title="Workloads">
            {(workloads ?? []).length === 0 ? (
              <p className="text-sm text-zinc-500">No workloads.</p>
            ) : (
              <ul className="space-y-1 text-sm">
                {workloads!.map((w) => (
                  <li key={w.id} className="flex items-center justify-between">
                    <span className="text-zinc-300">
                      {w.service_name}
                      {w.replica > 0 && ` #${w.replica}`}
                    </span>
                    <span className="flex items-center gap-2">
                      <Badge>{w.runtime_class}</Badge>
                      <StatusBadge status={w.state} />
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      )}
    </>
  );
}

export function RuntimeLogs({ envId, deploymentId }: { envId: string; deploymentId?: string }) {
  const q = useQuery({
    queryKey: ["runtime-logs", envId, deploymentId],
    queryFn: () => get<RuntimeLogLine[]>(`/api/v2/environments/${envId}/logs?tail=500${deploymentId ? `&deployment=${deploymentId}` : ""}`),
    refetchInterval: 4000,
  });
  if (q.error) return <Alert>{errorMessage(q.error)}</Alert>;
  return (
    <LogView
      lines={(q.data ?? []).map((l, i) => ({ key: `${l.time}-${i}`, text: `${l.time.slice(11, 19)} ${l.workload}${l.replica ? "#" + l.replica : ""} │ ${l.text}`, stream: l.stream }))}
      empty={q.isLoading ? "Loading…" : "No runtime output."}
    />
  );
}
