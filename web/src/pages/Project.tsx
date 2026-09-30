import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, NavLink, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { del, errorMessage, get, patch, post, put } from "../api/client";
import type { Deployment, Domain, EnvSummary, Member, ProjectDetail, SecretMeta, Volume } from "../api/types";
import { EnvEditor, type EnvRow } from "../components/EnvEditor";
import { Alert, Badge, Button, Card, Code, CopyButton, EmptyState, Field, Input, Loading, Modal, Select, StatusBadge, Textarea, Toggle, cx, useToast } from "../components/ui";
import { bytes, formatDate, shortSha, timeAgo } from "../lib/format";
import { RuntimeLogs } from "./Deployment";

const canWrite = (role?: string) => role === "owner" || role === "admin" || role === "developer";
const canAdmin = (role?: string) => role === "owner" || role === "admin";

export function ProjectPage() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["project", id], queryFn: () => get<ProjectDetail>(`/api/v2/projects/${id}`), refetchInterval: 8000 });
  if (q.isLoading) return <Loading />;
  if (q.error) return <Alert>{errorMessage(q.error)}</Alert>;
  const { project, environments } = q.data!;
  const prod = environments.find((e) => e.kind === "production");
  const tabs = [
    { to: "", label: "Overview" },
    { to: "deployments", label: "Deployments" },
    { to: "env", label: "Environment variables", hide: !canWrite(project.role) },
    { to: "domains", label: "Domains" },
    { to: "logs", label: "Runtime logs" },
    { to: "settings", label: "Settings", hide: !canAdmin(project.role) },
  ];
  return (
    <>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">{project.name}</h1>
          <p className="mt-1 text-sm text-zinc-400">
            {project.repo_full_name || "CLI uploads"} · {project.production_branch}
            {project.trust_class !== "trusted" && (
              <Badge className="ml-2" tone={project.trust_class === "privileged" ? "red" : "amber"}>
                {project.trust_class}
              </Badge>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          {prod?.url && (
            <a href={prod.domains[0] ? `https://${prod.domains[0]}` : prod.url} target="_blank" rel="noreferrer noopener">
              <Button>Visit</Button>
            </a>
          )}
          {canWrite(project.role) && project.clone_url && <DeployButton projectId={project.id} envs={environments} />}
        </div>
      </div>
      <nav className="mb-6 flex gap-1 overflow-x-auto border-b border-zinc-800">
        {tabs
          .filter((t) => !t.hide)
          .map((t) => (
            <NavLink
              key={t.to}
              to={t.to === "" ? `/projects/${id}` : `/projects/${id}/${t.to}`}
              end
              className={({ isActive }) => cx("-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm", isActive ? "border-indigo-500 text-white" : "border-transparent text-zinc-400 hover:text-zinc-200")}
            >
              {t.label}
            </NavLink>
          ))}
      </nav>
      <Routes>
        <Route index element={<Overview d={q.data!} />} />
        <Route path="deployments" element={<DeploymentsList projectId={id} envs={environments} />} />
        <Route path="env" element={<Secrets projectId={id} envs={environments} />} />
        <Route path="domains" element={<Domains d={q.data!} />} />
        <Route path="logs" element={<LogsTab envs={environments} />} />
        <Route path="settings" element={<Settings d={q.data!} />} />
      </Routes>
    </>
  );
}

function DeployButton({ projectId, envs }: { projectId: string; envs: EnvSummary[] }) {
  const [open, setOpen] = useState(false);
  const [env, setEnv] = useState("production");
  const [ref, setRef] = useState("");
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();
  const toast = useToast();
  const go = async () => {
    setBusy(true);
    try {
      const body: any = { environment: env };
      if (/^[0-9a-f]{40}$/.test(ref)) body.sha = ref;
      else if (ref) body.branch = ref;
      const d = await post<Deployment>(`/api/v2/projects/${projectId}/deployments`, body);
      nav(`/deployments/${d.id}`);
    } catch (e) {
      toast("red", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button variant="primary" onClick={() => setOpen(true)}>
        Deploy
      </Button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="New deployment"
        footer={
          <Button variant="primary" loading={busy} onClick={go}>
            Deploy
          </Button>
        }
      >
        <Field label="Environment">
          <Select value={env} onChange={(e) => setEnv(e.target.value)}>
            {envs
              .filter((e) => e.kind !== "preview" && e.status === "active")
              .map((e) => (
                <option key={e.id} value={e.name}>
                  {e.name}
                </option>
              ))}
          </Select>
        </Field>
        <Field label="Branch or commit SHA" hint="Leave empty to deploy the head of the environment's branch.">
          <Input value={ref} onChange={(e) => setRef(e.target.value.trim())} className="font-mono" />
        </Field>
      </Modal>
    </>
  );
}

function DeploymentRow({ d, envName }: { d: Deployment; envName?: string }) {
  return (
    <Link to={`/deployments/${d.id}`} className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-zinc-900">
      <div className="min-w-0">
        <p className="truncate text-sm text-zinc-100">{d.commit_message ? d.commit_message.split("\n")[0] : d.trigger}</p>
        <p className="mt-0.5 truncate text-xs text-zinc-500">
          {envName && <span className="text-zinc-400">{envName} · </span>}#{d.generation} · {d.trigger}
          {shortSha(d.commit_sha) && (
            <>
              {" "}
              · <span className="font-mono">{shortSha(d.commit_sha)}</span> {d.branch}
            </>
          )}
          {d.commit_author && ` · ${d.commit_author}`}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <span className="text-xs text-zinc-500">{timeAgo(d.created_at)}</span>
        <StatusBadge status={d.status} />
      </div>
    </Link>
  );
}

function Overview({ d }: { d: ProjectDetail }) {
  const { environments } = d;
  const prod = environments.find((e) => e.kind === "production");
  const others = environments.filter((e) => e.kind !== "production" && e.status !== "deleted");
  return (
    <div className="space-y-6">
      {prod && <EnvCard env={prod} primary />}
      {others.length > 0 && (
        <Card title="Other environments" padded={false}>
          <ul className="divide-y divide-zinc-800">
            {others.map((e) => (
              <li key={e.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                <div className="min-w-0">
                  <p className="text-sm text-zinc-100">
                    {e.name} {e.kind === "preview" && <Badge tone="indigo">preview{e.pr_from_fork ? " · fork" : ""}</Badge>}
                  </p>
                  {e.url && (
                    <a href={e.url} target="_blank" rel="noreferrer noopener" className="text-xs text-indigo-300 hover:underline">
                      {e.url.replace(/^https?:\/\//, "")}
                    </a>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {e.status !== "active" && <Badge>{e.status}</Badge>}
                  {e.latest_deployment && (
                    <Link to={`/deployments/${e.latest_deployment.id}`}>
                      <StatusBadge status={e.latest_deployment.status} />
                    </Link>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

function EnvCard({ env, primary }: { env: EnvSummary; primary?: boolean }) {
  const cur = env.current_deployment;
  const latest = env.latest_deployment;
  return (
    <Card title={primary ? "Production" : env.name}>
      <div className="grid gap-6 md:grid-cols-2">
        <div className="space-y-3">
          <div>
            <p className="text-xs uppercase tracking-wide text-zinc-500">Domains</p>
            <ul className="mt-1 space-y-1">
              {env.url && (
                <li>
                  <a className="text-sm text-indigo-300 hover:underline" href={env.url} target="_blank" rel="noreferrer noopener">
                    {env.url.replace(/^https?:\/\//, "")}
                  </a>
                </li>
              )}
              {env.domains.map((h) => (
                <li key={h}>
                  <a className="text-sm text-indigo-300 hover:underline" href={`https://${h}`} target="_blank" rel="noreferrer noopener">
                    {h}
                  </a>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-zinc-500">Branch</p>
            <p className="text-sm text-zinc-200">{env.branch}</p>
          </div>
        </div>
        <div className="space-y-3">
          <div>
            <p className="text-xs uppercase tracking-wide text-zinc-500">Serving</p>
            {cur ? (
              <Link to={`/deployments/${cur.id}`} className="mt-1 block text-sm text-zinc-200 hover:text-white">
                #{cur.generation} {cur.commit_message ? `· ${cur.commit_message.split("\n")[0]}` : ""} <span className="font-mono text-xs text-zinc-500">{shortSha(cur.commit_sha)}</span>
                <span className="block text-xs text-zinc-500">{timeAgo(cur.finished_at ?? cur.created_at)}</span>
              </Link>
            ) : (
              <p className="text-sm text-zinc-500">Nothing deployed yet</p>
            )}
          </div>
          {latest && latest.id !== cur?.id && (
            <div>
              <p className="text-xs uppercase tracking-wide text-zinc-500">Latest</p>
              <Link to={`/deployments/${latest.id}`} className="mt-1 flex items-center gap-2 text-sm text-zinc-200">
                <StatusBadge status={latest.status} /> #{latest.generation}
              </Link>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

function DeploymentsList({ projectId, envs }: { projectId: string; envs: EnvSummary[] }) {
  const [env, setEnv] = useState("");
  const q = useQuery({
    queryKey: ["deployments", projectId, env],
    queryFn: () => get<Deployment[]>(`/api/v2/projects/${projectId}/deployments?limit=100${env ? `&environment=${env}` : ""}`),
    refetchInterval: 5000,
  });
  const names = Object.fromEntries(envs.map((e) => [e.id, e.name]));
  return (
    <Card
      title="Deployments"
      padded={false}
      actions={
        <Select value={env} onChange={(e) => setEnv(e.target.value)} className="w-44 py-1">
          <option value="">All environments</option>
          {envs.map((e) => (
            <option key={e.id} value={e.name}>
              {e.name}
            </option>
          ))}
        </Select>
      }
    >
      {q.isLoading && <Loading />}
      {q.data?.length === 0 && <p className="p-6 text-sm text-zinc-500">No deployments.</p>}
      <div className="divide-y divide-zinc-800">
        {q.data?.map((d) => (
          <DeploymentRow key={d.id} d={d} envName={names[d.environment_id]} />
        ))}
      </div>
    </Card>
  );
}

function LogsTab({ envs }: { envs: EnvSummary[] }) {
  const live = envs.filter((e) => e.current_deployment_id);
  const [env, setEnv] = useState(live[0]?.id ?? "");
  if (!live.length) return <EmptyState title="Nothing is running">Deploy the project to see runtime output.</EmptyState>;
  return (
    <div className="space-y-3">
      <Select value={env} onChange={(e) => setEnv(e.target.value)} className="w-56">
        {live.map((e) => (
          <option key={e.id} value={e.id}>
            {e.name}
          </option>
        ))}
      </Select>
      <RuntimeLogs envId={env} />
    </div>
  );
}

// ---- secrets -------------------------------------------------------------------

function Secrets({ projectId, envs }: { projectId: string; envs: EnvSummary[] }) {
  const scopes = [
    ...envs.filter((e) => e.kind !== "preview").map((e) => ({ key: `environment:${e.name}`, label: e.name, scope: "environment", env: e.name })),
    { key: "preview", label: "All previews", scope: "preview", env: "" },
    { key: "project", label: "Shared (all non-preview)", scope: "project", env: "" },
  ];
  const [sel, setSel] = useState(scopes[0].key);
  const cur = scopes.find((s) => s.key === sel)!;
  const qs = `scope=${cur.scope}${cur.env ? `&environment=${encodeURIComponent(cur.env)}` : ""}`;
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["secrets", projectId, sel], queryFn: () => get<SecretMeta[]>(`/api/v2/projects/${projectId}/secrets?${qs}`) });
  const [rows, setRows] = useState<EnvRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [revealed, setRevealed] = useState<Record<string, string>>({});

  const save = async () => {
    setBusy(true);
    try {
      for (const r of rows.filter((r) => r.key)) {
        await put(`/api/v2/projects/${projectId}/secrets`, { scope: cur.scope, environment: cur.env, name: r.key, value: r.value, sensitive: true });
      }
      setRows([]);
      toast("green", "Saved. Redeploy to apply changes to running workloads.");
      qc.invalidateQueries({ queryKey: ["secrets", projectId] });
    } catch (e) {
      toast("red", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const remove = async (name: string) => {
    if (!confirm(`Delete ${name}?`)) return;
    try {
      await del(`/api/v2/projects/${projectId}/secrets?${qs}&name=${encodeURIComponent(name)}`);
      qc.invalidateQueries({ queryKey: ["secrets", projectId] });
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  const reveal = async (m: SecretMeta) => {
    try {
      const r = await post<{ value: string }>(`/api/v2/projects/${projectId}/secrets/${m.id}/reveal`, { reason: "dashboard" });
      setRevealed((x) => ({ ...x, [m.id]: r.value }));
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
      <div className="space-y-1">
        {scopes.map((s) => (
          <button
            key={s.key}
            onClick={() => {
              setSel(s.key);
              setRevealed({});
            }}
            className={cx("block w-full rounded-md px-3 py-2 text-left text-sm", sel === s.key ? "bg-zinc-800 text-white" : "text-zinc-400 hover:bg-zinc-900")}
          >
            {s.label}
          </button>
        ))}
        <p className="px-3 pt-3 text-xs text-zinc-500">Previews never inherit production values. Values are injected as files and, by default, environment variables.</p>
      </div>
      <div className="space-y-6">
        <Card title={`Variables · ${cur.label}`} padded={false}>
          {q.isLoading && <Loading />}
          {q.error && <Alert>{errorMessage(q.error)}</Alert>}
          {q.data?.length === 0 && <p className="p-4 text-sm text-zinc-500">No variables in this scope.</p>}
          <ul className="divide-y divide-zinc-800">
            {q.data?.map((m) => (
              <li key={m.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                <div className="min-w-0">
                  <p className="font-mono text-sm text-zinc-100">{m.name}</p>
                  <p className="truncate text-xs text-zinc-500">
                    {revealed[m.id] !== undefined ? <span className="font-mono text-amber-200">{revealed[m.id]}</span> : m.sensitive ? "••••••••" : m.preview} · v{m.version} · {timeAgo(m.created_at)}
                  </p>
                </div>
                <div className="flex gap-1">
                  {m.sensitive && revealed[m.id] === undefined && (
                    <Button size="sm" variant="ghost" onClick={() => reveal(m)}>
                      Reveal
                    </Button>
                  )}
                  <Button size="sm" variant="ghost" onClick={() => setRows([...rows, { key: m.name, value: "" }])}>
                    Update
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => remove(m.name)}>
                    Delete
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Add or update">
          <EnvEditor rows={rows} onChange={setRows} />
          {rows.length > 0 && (
            <Button className="mt-4" variant="primary" loading={busy} onClick={save}>
              Save {rows.filter((r) => r.key).length} variable(s)
            </Button>
          )}
        </Card>
      </div>
    </div>
  );
}

// ---- domains -------------------------------------------------------------------

function Domains({ d }: { d: ProjectDetail }) {
  const { project, environments } = d;
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["domains", project.id], queryFn: () => get<Domain[]>(`/api/v2/projects/${project.id}/domains`), refetchInterval: 10000 });
  const [host, setHost] = useState("");
  const [env, setEnv] = useState("production");
  const [busy, setBusy] = useState("");
  const [checks, setChecks] = useState<Record<string, any>>({});
  const admin = canAdmin(project.role);

  const claim = async () => {
    setBusy("claim");
    try {
      await post(`/api/v2/projects/${project.id}/domains`, { hostname: host, environment: env });
      setHost("");
      qc.invalidateQueries({ queryKey: ["domains", project.id] });
    } catch (e) {
      toast("red", errorMessage(e));
    } finally {
      setBusy("");
    }
  };
  const verify = async (dom: Domain) => {
    setBusy(dom.id);
    try {
      const r = await post<{ check: any }>(`/api/v2/domains/${dom.id}/verify`);
      setChecks((c) => ({ ...c, [dom.id]: r.check }));
      toast("green", `${dom.hostname} verified — HTTPS is being provisioned`);
    } catch (e: any) {
      if (e?.body?.check) setChecks((c) => ({ ...c, [dom.id]: e.body.check }));
      toast("red", errorMessage(e));
    } finally {
      setBusy("");
      qc.invalidateQueries({ queryKey: ["domains", project.id] });
    }
  };
  const detach = async (dom: Domain) => {
    if (!confirm(`Detach ${dom.hostname}? It stops serving immediately and a future claim needs a fresh DNS proof.`)) return;
    try {
      await del(`/api/v2/domains/${dom.id}`);
      qc.invalidateQueries({ queryKey: ["domains", project.id] });
      qc.invalidateQueries({ queryKey: ["project", project.id] });
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };

  const envName = (id: string) => environments.find((e) => e.id === id)?.name ?? "";
  const visible = (q.data ?? []).filter((x) => x.status !== "expired");
  return (
    <div className="space-y-6">
      <Card title="Generated URLs" padded={false}>
        <ul className="divide-y divide-zinc-800">
          {environments
            .filter((e) => e.url)
            .map((e) => (
              <li key={e.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
                <a className="text-indigo-300 hover:underline" href={e.url} target="_blank" rel="noreferrer noopener">
                  {e.url!.replace(/^https?:\/\//, "")}
                </a>
                <span className="text-xs text-zinc-500">{e.name}</span>
              </li>
            ))}
        </ul>
      </Card>
      {admin && (
        <Card title="Add a custom domain">
          <form
            className="flex flex-wrap gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void claim();
            }}
          >
            <Input placeholder="www.example.com" value={host} onChange={(e) => setHost(e.target.value.trim())} className="max-w-sm flex-1" />
            <Select value={env} onChange={(e) => setEnv(e.target.value)} className="w-44">
              {environments
                .filter((e) => e.kind !== "preview")
                .map((e) => (
                  <option key={e.id} value={e.name}>
                    {e.name}
                  </option>
                ))}
            </Select>
            <Button type="submit" variant="primary" loading={busy === "claim"} disabled={!host}>
              Add
            </Button>
          </form>
          <p className="mt-2 text-xs text-zinc-500">Ownership is proven with a fresh TXT record checked directly against your domain's authoritative name servers. Any registrar works.</p>
        </Card>
      )}
      {visible.map((dom) => (
        <Card
          key={dom.id}
          title={
            <span className="flex items-center gap-2">
              {dom.hostname} <DomainBadge d={dom} />
            </span>
          }
          actions={
            admin && (
              <>
                {dom.status === "pending" && (
                  <Button size="sm" variant="primary" loading={busy === dom.id} onClick={() => verify(dom)}>
                    Verify
                  </Button>
                )}
                {["pending", "active", "verified"].includes(dom.status) && (
                  <Button size="sm" variant="ghost" onClick={() => detach(dom)}>
                    {dom.status === "pending" ? "Cancel" : "Detach"}
                  </Button>
                )}
              </>
            )
          }
        >
          <p className="mb-3 text-xs text-zinc-500">
            {envName(dom.environment_id)} · added {timeAgo(dom.created_at)}
            {dom.verified_at && ` · verified ${formatDate(dom.verified_at)}`}
          </p>
          {dom.status === "pending" && dom.instructions && <DNSInstructions i={dom.instructions} host={dom.hostname} />}
          {checks[dom.id] && <CheckResult c={checks[dom.id]} />}
        </Card>
      ))}
    </div>
  );
}

function DomainBadge({ d }: { d: Domain }) {
  if (d.status === "active") {
    const t = d.tls_status;
    return <Badge tone={t === "active" ? "green" : t === "error" || t === "expired" ? "red" : "amber"}>{t === "active" ? "HTTPS active" : t === "none" ? "active" : `HTTPS ${t}`}</Badge>;
  }
  return <Badge tone={d.status === "pending" ? "amber" : "gray"}>{d.status}</Badge>;
}

function DNSInstructions({ i, host }: { i: NonNullable<Domain["instructions"]>; host: string }) {
  const apex = host.split(".").length === 2;
  return (
    <div className="space-y-3 text-sm">
      <p className="text-zinc-300">Add these records at your DNS provider, then press Verify:</p>
      <div className="overflow-x-auto rounded-md border border-zinc-800">
        <table className="w-full text-left text-xs">
          <thead className="bg-zinc-900 text-zinc-500">
            <tr>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Value</th>
              <th />
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800 font-mono">
            <tr>
              <td className="px-3 py-2">TXT</td>
              <td className="px-3 py-2">{i.txt_name}</td>
              <td className="break-all px-3 py-2">{i.txt_value}</td>
              <td className="px-2">
                <CopyButton value={i.txt_value} />
              </td>
            </tr>
            {(i.routing.hosts ?? []).map((h) =>
              apex ? (
                <tr key={h}>
                  <td className="px-3 py-2">ALIAS/A</td>
                  <td className="px-3 py-2">{host}</td>
                  <td className="px-3 py-2">{h} (or its A records)</td>
                  <td />
                </tr>
              ) : (
                <tr key={h}>
                  <td className="px-3 py-2">CNAME</td>
                  <td className="px-3 py-2">{host}</td>
                  <td className="px-3 py-2">{h}</td>
                  <td className="px-2">
                    <CopyButton value={h} />
                  </td>
                </tr>
              ),
            )}
            {(i.routing.ips ?? []).map((ip) => (
              <tr key={ip}>
                <td className="px-3 py-2">{ip.includes(":") ? "AAAA" : "A"}</td>
                <td className="px-3 py-2">{host}</td>
                <td className="px-3 py-2">{ip}</td>
                <td className="px-2">
                  <CopyButton value={ip} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {i.note && <Alert tone="blue">{i.note}</Alert>}
      <p className="text-xs text-zinc-500">This claim expires {formatDate(i.expires_at)}. DNS changes can take a few minutes to reach every name server.</p>
    </div>
  );
}

function CheckResult({ c }: { c: any }) {
  return (
    <div className="mt-3 space-y-2">
      <Alert tone={c.proven ? "green" : "amber"} title={c.proven ? "Ownership proven" : "Ownership not proven yet"}>
        {c.ownership}
      </Alert>
      {c.routing && (
        <Alert tone={c.routing.ok ? "green" : "amber"} title={c.routing.ok ? "Routing OK" : "Routing"}>
          {c.routing.detail}
        </Alert>
      )}
    </div>
  );
}

// ---- settings ------------------------------------------------------------------

function Settings({ d }: { d: ProjectDetail }) {
  const { project } = d;
  const qc = useQueryClient();
  const toast = useToast();
  const nav = useNavigate();
  const [f, setF] = useState({
    production_branch: project.production_branch,
    root_dir: project.root_dir,
    auto_deploy: project.auto_deploy,
    previews_enabled: project.previews_enabled,
    allow_public_forks: project.allow_public_forks,
    prefer_gvisor: project.prefer_gvisor,
    trust_class: project.trust_class,
    build: project.build_overrides ?? {},
    config_override: project.config_override ?? "",
  });
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      await patch(`/api/v2/projects/${project.id}`, f);
      toast("green", "Settings saved");
      qc.invalidateQueries({ queryKey: ["project", project.id] });
    } catch (e) {
      toast("red", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (prompt(`Type the project name (${project.name}) to delete it and all its environments.`) !== project.name) return;
    try {
      await del(`/api/v2/projects/${project.id}`);
      qc.invalidateQueries({ queryKey: ["projects"] });
      nav("/");
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  return (
    <div className="space-y-6">
      <Card title="Source & automation">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Production branch">
            <Input value={f.production_branch} onChange={(e) => setF({ ...f, production_branch: e.target.value })} />
          </Field>
          <Field label="Root directory">
            <Input value={f.root_dir} onChange={(e) => setF({ ...f, root_dir: e.target.value })} />
          </Field>
        </div>
        <div className="mt-5 space-y-4">
          <Toggle checked={f.auto_deploy} onChange={(v) => setF({ ...f, auto_deploy: v })} label="Deploy on push" />
          <Toggle checked={f.previews_enabled} onChange={(v) => setF({ ...f, previews_enabled: v })} label="Pull request previews" />
          <Toggle
            checked={f.allow_public_forks}
            onChange={(v) => setF({ ...f, allow_public_forks: v })}
            label="Allow previews from forks"
            description="Fork code always builds and runs as Untrusted in the gVisor sandbox with no production secrets. If the sandbox is unavailable these previews fail closed."
          />
        </div>
      </Card>
      <Card title="Isolation">
        <div className="space-y-4">
          <Field label="Trust class" hint="Changing trust class applies to the next deployment.">
            <Select value={f.trust_class} onChange={(e) => setF({ ...f, trust_class: e.target.value as any })}>
              <option value="trusted">Trusted</option>
              <option value="untrusted">Untrusted (gVisor)</option>
              <option value="privileged">Privileged / Unsafe (owner only)</option>
            </Select>
          </Field>
          <Toggle checked={f.prefer_gvisor} onChange={(v) => setF({ ...f, prefer_gvisor: v })} label="Prefer gVisor for trusted code" description="Extra defence in depth when the host supports it." />
        </div>
      </Card>
      <Card title="Build">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Strategy">
            <Select value={f.build.strategy ?? ""} onChange={(e) => setF({ ...f, build: { ...f.build, strategy: e.target.value } })}>
              <option value="">Auto-detect</option>
              <option value="dockerfile">Dockerfile</option>
              <option value="static">Static</option>
              <option value="buildpacks">Buildpacks</option>
              <option value="nixpacks">Nixpacks</option>
            </Select>
          </Field>
          <Field label="Port">
            <Input type="number" value={f.build.port || ""} onChange={(e) => setF({ ...f, build: { ...f.build, port: Number(e.target.value) || 0 } })} />
          </Field>
          <Field label="Build command">
            <Input className="font-mono" value={f.build.build_command ?? ""} onChange={(e) => setF({ ...f, build: { ...f.build, build_command: e.target.value } })} />
          </Field>
          <Field label="Start command">
            <Input className="font-mono" value={f.build.start_command ?? ""} onChange={(e) => setF({ ...f, build: { ...f.build, start_command: e.target.value } })} />
          </Field>
          <Field label="Output directory">
            <Input className="font-mono" value={f.build.output_dir ?? ""} onChange={(e) => setF({ ...f, build: { ...f.build, output_dir: e.target.value } })} />
          </Field>
        </div>
        <div className="mt-4">
          <Field label="opendeploy.yaml override" hint="Admin-side configuration that takes precedence over the repository's file. The repository can never raise its own privileges.">
            <Textarea rows={6} value={f.config_override} onChange={(e) => setF({ ...f, config_override: e.target.value })} placeholder="version: 2" />
          </Field>
        </div>
      </Card>
      <div>
        <Button variant="primary" loading={busy} onClick={save}>
          Save settings
        </Button>
      </div>
      <PreviewProtection projectId={project.id} />
      <Members projectId={project.id} />
      <Volumes projectId={project.id} />
      <Card title="Danger zone">
        <div className="flex items-center justify-between gap-4">
          <p className="text-sm text-zinc-400">Delete this project, stop its workloads and detach its domains. Protected volumes are retained.</p>
          <Button variant="danger" onClick={remove}>
            Delete project
          </Button>
        </div>
      </Card>
    </div>
  );
}

function PreviewProtection({ projectId }: { projectId: string }) {
  const toast = useToast();
  const q = useQuery({ queryKey: ["preview-protection", projectId], queryFn: () => get<{ enabled: boolean; user: string }>(`/api/v2/projects/${projectId}/preview-protection`) });
  const [f, setF] = useState({ enabled: false, user: "", password: "" });
  useEffect(() => {
    if (q.data) setF((x) => ({ ...x, enabled: q.data.enabled, user: q.data.user }));
  }, [q.data]);
  const save = async () => {
    try {
      await put(`/api/v2/projects/${projectId}/preview-protection`, f);
      toast("green", "Preview protection updated");
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  return (
    <Card title="Preview protection">
      <Toggle checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label="Require a password for preview URLs" description="HTTP basic authentication at the edge, for preview environments only." />
      {f.enabled && (
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Field label="Username">
            <Input value={f.user} onChange={(e) => setF({ ...f, user: e.target.value })} />
          </Field>
          <Field label="Password" hint="At least 8 characters">
            <Input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" />
          </Field>
        </div>
      )}
      <Button className="mt-4" onClick={save}>
        Save
      </Button>
    </Card>
  );
}

function Members({ projectId }: { projectId: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["members", projectId], queryFn: () => get<Member[]>(`/api/v2/projects/${projectId}/members`) });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("developer");
  const add = async () => {
    try {
      await put(`/api/v2/projects/${projectId}/members`, { email, role });
      setEmail("");
      qc.invalidateQueries({ queryKey: ["members", projectId] });
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  const remove = async (m: Member) => {
    try {
      await del(`/api/v2/projects/${projectId}/members/${m.user_id}`);
      qc.invalidateQueries({ queryKey: ["members", projectId] });
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  return (
    <Card title="Members" padded={false}>
      <ul className="divide-y divide-zinc-800">
        {q.data?.map((m) => (
          <li key={m.user_id} className="flex items-center justify-between px-4 py-2.5">
            <div>
              <p className="text-sm text-zinc-100">{m.name || m.email}</p>
              <p className="text-xs text-zinc-500">{m.email}</p>
            </div>
            <div className="flex items-center gap-2">
              <Badge>{m.role}</Badge>
              <Button size="sm" variant="ghost" onClick={() => remove(m)}>
                Remove
              </Button>
            </div>
          </li>
        ))}
      </ul>
      <form
        className="flex flex-wrap gap-2 border-t border-zinc-800 p-4"
        onSubmit={(e) => {
          e.preventDefault();
          void add();
        }}
      >
        <Input type="email" placeholder="user@example.com" value={email} onChange={(e) => setEmail(e.target.value)} className="max-w-xs flex-1" />
        <Select value={role} onChange={(e) => setRole(e.target.value)} className="w-40">
          <option value="viewer">Viewer</option>
          <option value="developer">Developer</option>
          <option value="admin">Project admin</option>
        </Select>
        <Button type="submit" disabled={!email}>
          Add member
        </Button>
      </form>
    </Card>
  );
}

function Volumes({ projectId }: { projectId: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["volumes", projectId], queryFn: () => get<Volume[]>(`/api/v2/projects/${projectId}/volumes`) });
  if (!q.data?.length) return null;
  const toggle = async (v: Volume) => {
    try {
      await patch(`/api/v2/projects/${projectId}/volumes/${v.id}`, { deletion_protection: !v.deletion_protection });
      qc.invalidateQueries({ queryKey: ["volumes", projectId] });
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  return (
    <Card title="Volumes" padded={false}>
      <ul className="divide-y divide-zinc-800">
        {q.data.map((v) => (
          <li key={v.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
            <div>
              <p className="text-zinc-100">
                {v.name} <Code>{v.mount_target}</Code>
              </p>
              <p className="text-xs text-zinc-500">
                {bytes(v.size_bytes)} · {v.status}
              </p>
            </div>
            <Toggle checked={v.deletion_protection} onChange={() => toggle(v)} label="Protected" />
          </li>
        ))}
      </ul>
    </Card>
  );
}
