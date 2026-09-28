import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink, Route, Routes } from "react-router-dom";
import { errorMessage, get, patch, post, put, del } from "../api/client";
import type { AuditEvent, GitStatus, Job, SecretMeta, User } from "../api/types";
import { useAuth } from "../auth";
import { Alert, Badge, Button, Card, Code, EmptyState, Field, Input, Loading, PageHeader, Select, Toggle, cx, useToast } from "../components/ui";
import { formatDate, timeAgo } from "../lib/format";

export function PlatformPage() {
  const { user } = useAuth();
  const owner = user?.role === "owner";
  const tabs = [
    { to: "", label: "Status" },
    { to: "github", label: "GitHub", owner: true },
    { to: "users", label: "Users" },
    { to: "variables", label: "Instance variables", owner: true },
    { to: "audit", label: "Audit log", owner: true },
    { to: "jobs", label: "Jobs", owner: true },
  ].filter((t) => !t.owner || owner);
  return (
    <>
      <PageHeader title="Platform" subtitle="Node status, integrations and administration." />
      <nav className="mb-6 flex gap-1 overflow-x-auto border-b border-zinc-800">
        {tabs.map((t) => (
          <NavLink
            key={t.to}
            to={t.to === "" ? "/settings" : `/settings/${t.to}`}
            end
            className={({ isActive }) => cx("-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm", isActive ? "border-indigo-500 text-white" : "border-transparent text-zinc-400 hover:text-zinc-200")}
          >
            {t.label}
          </NavLink>
        ))}
      </nav>
      <Routes>
        <Route index element={<Status />} />
        <Route path="github" element={<GitHub />} />
        <Route path="users" element={<Users />} />
        <Route path="variables" element={<InstanceVars />} />
        <Route path="audit" element={<Audit />} />
        <Route path="jobs" element={<Jobs />} />
      </Routes>
    </>
  );
}

function Yes({ ok, label }: { ok: boolean; label: string }) {
  return (
    <li className="flex items-center justify-between py-1.5 text-sm">
      <span className="text-zinc-300">{label}</span>
      <Badge tone={ok ? "green" : "amber"}>{ok ? "available" : "unavailable"}</Badge>
    </li>
  );
}

function Status() {
  const q = useQuery({ queryKey: ["system"], queryFn: () => get<any>("/api/v2/system"), refetchInterval: 15000 });
  if (q.isLoading) return <Loading />;
  if (q.error) return <Alert>{errorMessage(q.error)}</Alert>;
  const s = q.data;
  const caps = s.capabilities ?? {};
  return (
    <div className="space-y-6">
      {s.degraded && (
        <Alert title="Degraded read-only mode">
          {s.degraded} — deployments and changes are paused until state is repaired or restored.
        </Alert>
      )}
      {s.dev_mode && <Alert tone="amber" title="Insecure development mode">IPC identities are self-declared. Never run production workloads in this mode.</Alert>}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Node">
          <dl className="grid grid-cols-2 gap-y-2 text-sm">
            <dt className="text-zinc-500">Version</dt>
            <dd>{s.version}</dd>
            <dt className="text-zinc-500">Profile</dt>
            <dd>{s.profile}</dd>
            <dt className="text-zinc-500">Ingress</dt>
            <dd>{s.ingress_mode}</dd>
            <dt className="text-zinc-500">Generated domains</dt>
            <dd>
              <Code>*.{s.base_domain}</Code>
            </dd>
            <dt className="text-zinc-500">Edge routes</dt>
            <dd>{s.edge ? s.edge.routes : <span className="text-red-300">{s.edge_error}</span>}</dd>
            <dt className="text-zinc-500">MFA required</dt>
            <dd>{s.require_mfa ? "yes (owners & admins)" : "no"}</dd>
          </dl>
        </Card>
        <Card title="Isolation capabilities">
          <ul className="divide-y divide-zinc-800">
            <Yes ok={!!caps.runtimes?.runc} label="Container runtime (runc)" />
            <Yes ok={!!caps.runtimes?.runsc} label="gVisor sandbox (Untrusted class)" />
            <Yes ok={!!caps.runtimes?.vm} label="MicroVM runtime" />
            <Yes ok={!!caps.rootless_build} label="Rootless builds" />
            <Yes ok={!!caps.network_policy && !String(caps.network_note ?? "").startsWith("INSECURE")} label="Network policy (egressd)" />
          </ul>
          {caps.network_note && <p className="mt-2 text-xs text-amber-300">{caps.network_note}</p>}
          {!caps.runtimes?.runsc && <p className="mt-2 text-xs text-zinc-500">Without gVisor, Untrusted projects and fork previews fail closed by design.</p>}
        </Card>
        {s.relay && (
          <Card title="Relay tunnel">
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <dt className="text-zinc-500">Connected</dt>
              <dd>
                <Badge tone={s.relay.connected ? "green" : "red"}>{s.relay.connected ? "yes" : "no"}</Badge>
              </dd>
              <dt className="text-zinc-500">Instance</dt>
              <dd>
                {s.relay.tenant}/{s.relay.instance}
              </dd>
              <dt className="text-zinc-500">Credential valid until</dt>
              <dd>{formatDate(s.relay.cert_until)}</dd>
              <dt className="text-zinc-500">Routed hosts</dt>
              <dd>{s.relay.accepted?.length ?? 0}</dd>
            </dl>
            {s.relay.rejected && Object.keys(s.relay.rejected).length > 0 && (
              <div className="mt-3 space-y-1">
                {Object.entries(s.relay.rejected).map(([h, why]) => (
                  <Alert key={h} tone="amber" title={h}>
                    {String(why)}
                  </Alert>
                ))}
              </div>
            )}
          </Card>
        )}
        {s.audit && (
          <Card title="Audit chain">
            <p className="text-sm">
              <Badge tone={s.audit.ok ? "green" : "red"}>{s.audit.ok ? "intact" : "BROKEN"}</Badge> <span className="ml-2 text-zinc-400">{s.audit.count} events · {s.audit.checkpoints_verified} signed checkpoints verified</span>
            </p>
            {s.audit.broken_at ? <p className="mt-2 text-xs text-red-300">Chain broken at event #{s.audit.broken_at}</p> : null}
          </Card>
        )}
      </div>
    </div>
  );
}

function GitHub() {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["git"], queryFn: () => get<GitStatus>("/api/v2/git") });
  const [org, setOrg] = useState("");
  const [name, setName] = useState("OpenDeploy");
  const [checks, setChecks] = useState(true);
  const [busy, setBusy] = useState(false);

  const register = async () => {
    setBusy(true);
    try {
      const r = await post<{ post_url: string; manifest: any }>("/api/v2/git/github/manifest", { organization: org, name, with_checks: checks });
      // GitHub's manifest flow requires a top-level form POST.
      const form = document.createElement("form");
      form.method = "POST";
      form.action = r.post_url;
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "manifest";
      input.value = JSON.stringify(r.manifest);
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
    } catch (e) {
      toast("red", errorMessage(e));
      setBusy(false);
    }
  };
  const sync = async () => {
    try {
      await post("/api/v2/git/github/sync");
      qc.invalidateQueries({ queryKey: ["git"] });
      toast("green", "Installations refreshed");
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };

  if (q.isLoading) return <Loading />;
  const g = q.data!;
  return (
    <div className="space-y-6">
      {!g.configured ? (
        <Card title="Register a GitHub App">
          <p className="mb-4 text-sm text-zinc-400">
            OpenDeploy creates a private GitHub App for this node with read-only repository contents access{checks ? " and check-run status" : ""}. Webhooks go to <Code>{g.public_url}/webhooks/github</Code>, which must be
            reachable from GitHub.
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Organization (optional)" hint="Leave empty to create the app on your personal account.">
              <Input value={org} onChange={(e) => setOrg(e.target.value.trim())} />
            </Field>
            <Field label="App name">
              <Input value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
          </div>
          <div className="mt-4">
            <Toggle checked={checks} onChange={setChecks} label="Report deployment status as GitHub checks" />
          </div>
          <Button className="mt-4" variant="primary" loading={busy} onClick={register}>
            Create GitHub App
          </Button>
        </Card>
      ) : (
        <Card
          title="GitHub App"
          actions={
            <>
              <Button size="sm" onClick={sync}>
                Refresh installations
              </Button>
              {g.install_url && (
                <a href={g.install_url} rel="noreferrer">
                  <Button size="sm" variant="primary">
                    Install on another account
                  </Button>
                </a>
              )}
            </>
          }
          padded={false}
        >
          {g.connections.length === 0 ? (
            <p className="p-4 text-sm text-zinc-500">The app is registered but not installed on any account yet.</p>
          ) : (
            <ul className="divide-y divide-zinc-800">
              {g.connections.map((c) => (
                <li key={c.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
                  <span>
                    {c.account_login} <span className="text-xs text-zinc-500">({c.account_type})</span>
                  </span>
                  <Badge tone={c.status === "active" ? "green" : "amber"}>{c.status}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
      {g.error && g.configured && <Alert tone="amber">{g.error}</Alert>}
    </div>
  );
}

function Users() {
  const { user: me } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["users"], queryFn: () => get<User[]>("/api/v2/users") });
  const [f, setF] = useState({ email: "", name: "", role: "developer", password: "" });
  const owner = me?.role === "owner";
  const create = async () => {
    try {
      await post("/api/v2/users", f);
      setF({ email: "", name: "", role: "developer", password: "" });
      qc.invalidateQueries({ queryKey: ["users"] });
      toast("green", "User created");
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  const update = async (u: User, body: any) => {
    try {
      await patch(`/api/v2/users/${u.id}`, body);
      qc.invalidateQueries({ queryKey: ["users"] });
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  if (q.error) return <Alert>{errorMessage(q.error)}</Alert>;
  return (
    <div className="space-y-6">
      <Card title="Users" padded={false}>
        {q.isLoading && <Loading />}
        <ul className="divide-y divide-zinc-800">
          {q.data?.map((u) => (
            <li key={u.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
              <div>
                <p className="text-sm text-zinc-100">
                  {u.name || u.email} {u.disabled && <Badge tone="red">disabled</Badge>}
                </p>
                <p className="text-xs text-zinc-500">
                  {u.email} · {u.totp_enabled || u.webauthn_count > 0 ? "MFA on" : "no MFA"} · joined {timeAgo(u.created_at)}
                </p>
              </div>
              {owner && u.id !== me?.id ? (
                <div className="flex items-center gap-2">
                  <Select value={u.role} onChange={(e) => update(u, { role: e.target.value })} className="w-32 py-1">
                    <option value="owner">Owner</option>
                    <option value="admin">Admin</option>
                    <option value="developer">Developer</option>
                    <option value="viewer">Viewer</option>
                  </Select>
                  <Button size="sm" variant="ghost" onClick={() => update(u, { disabled: !u.disabled })}>
                    {u.disabled ? "Enable" : "Disable"}
                  </Button>
                  {(u.totp_enabled || u.webauthn_count > 0) && (
                    <Button size="sm" variant="ghost" onClick={() => confirm(`Reset MFA for ${u.email}?`) && update(u, { reset_mfa: true })}>
                      Reset MFA
                    </Button>
                  )}
                </div>
              ) : (
                <Badge>{u.role}</Badge>
              )}
            </li>
          ))}
        </ul>
      </Card>
      {owner && (
        <Card title="Add user">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Email">
              <Input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} />
            </Field>
            <Field label="Name">
              <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
            </Field>
            <Field label="Role" hint="Node role; project access is granted per project.">
              <Select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
                <option value="viewer">Viewer</option>
                <option value="developer">Developer</option>
                <option value="admin">Admin</option>
                <option value="owner">Owner</option>
              </Select>
            </Field>
            <Field label="Initial password" hint="Share it securely; admins and owners must enroll MFA at first sign-in.">
              <Input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" />
            </Field>
          </div>
          <Button className="mt-4" variant="primary" onClick={create} disabled={!f.email || !f.password}>
            Create user
          </Button>
        </Card>
      )}
    </div>
  );
}

function InstanceVars() {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["instance-secrets"], queryFn: () => get<SecretMeta[]>("/api/v2/secrets") });
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const save = async (body: any) => {
    try {
      await put("/api/v2/secrets", body);
      qc.invalidateQueries({ queryKey: ["instance-secrets"] });
      setName("");
      setValue("");
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  return (
    <div className="space-y-6">
      <Card title="Instance-wide defaults" padded={false}>
        <p className="px-4 pt-3 text-xs text-zinc-500">Available to every production and staging environment unless overridden by the project. Never inherited by previews.</p>
        {q.data?.length === 0 && <p className="p-4 text-sm text-zinc-500">None.</p>}
        <ul className="divide-y divide-zinc-800">
          {q.data?.map((m) => (
            <li key={m.id} className="flex items-center justify-between px-4 py-2.5">
              <span className="font-mono text-sm">{m.name}</span>
              <Button size="sm" variant="ghost" onClick={() => save({ name: m.name, delete: true })}>
                Delete
              </Button>
            </li>
          ))}
        </ul>
      </Card>
      <Card title="Add variable">
        <div className="flex flex-wrap gap-2">
          <Input placeholder="NAME" className="max-w-xs font-mono" value={name} onChange={(e) => setName(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_"))} />
          <Input placeholder="value" type="password" className="max-w-sm font-mono" value={value} onChange={(e) => setValue(e.target.value)} />
          <Button onClick={() => save({ name, value, sensitive: true })} disabled={!name}>
            Save
          </Button>
        </div>
      </Card>
    </div>
  );
}

function Audit() {
  const [action, setAction] = useState("");
  const [before, setBefore] = useState<number | undefined>();
  const q = useQuery({
    queryKey: ["audit", action, before],
    queryFn: () => get<AuditEvent[]>(`/api/v2/system/audit?limit=100${action ? `&action=${encodeURIComponent(action)}` : ""}${before ? `&before=${before}` : ""}`),
  });
  const v = useQuery({ queryKey: ["audit-verify"], queryFn: () => get<any>("/api/v2/system/audit/verify") });
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex gap-2">
          <Select value={action} onChange={(e) => (setAction(e.target.value), setBefore(undefined))} className="w-56">
            <option value="">All events</option>
            <option value="auth.">Authentication</option>
            <option value="deploy">Deployments</option>
            <option value="secret">Secrets</option>
            <option value="domain.">Domains</option>
            <option value="webhook.">Webhooks</option>
            <option value="project.">Projects</option>
            <option value="authz.deny">Denied authorisations</option>
          </Select>
        </div>
        {v.data && (
          <span className="text-sm">
            Chain <Badge tone={v.data.ok ? "green" : "red"}>{v.data.ok ? "verified" : "BROKEN"}</Badge>
          </span>
        )}
      </div>
      <Card padded={false}>
        {q.isLoading && <Loading />}
        {q.data?.length === 0 && <EmptyState title="No events" />}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-900 text-zinc-500">
              <tr>
                <th className="px-3 py-2">#</th>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Actor</th>
                <th className="px-3 py-2">Action</th>
                <th className="px-3 py-2">Resource</th>
                <th className="px-3 py-2">Result</th>
                <th className="px-3 py-2">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {q.data?.map((e) => (
                <tr key={e.seq} className="align-top">
                  <td className="px-3 py-2 text-zinc-500">{e.seq}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-zinc-400">{formatDate(e.time)}</td>
                  <td className="px-3 py-2">
                    {e.actor_type}
                    {e.actor_id && <span className="block text-zinc-500">{e.actor_id}</span>}
                    {e.source_ip && <span className="block text-zinc-600">{e.source_ip}</span>}
                  </td>
                  <td className="px-3 py-2 font-mono text-zinc-200">{e.action}</td>
                  <td className="px-3 py-2 text-zinc-400">
                    {e.resource_type} {e.resource_id}
                  </td>
                  <td className="px-3 py-2">
                    <Badge tone={e.result === "success" ? "green" : e.result === "denied" ? "amber" : "red"}>{e.result}</Badge>
                  </td>
                  <td className="max-w-sm break-all px-3 py-2 font-mono text-zinc-500">
                    {Object.entries(e.details ?? {})
                      .map(([k, v]) => `${k}=${v}`)
                      .join(" ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      {q.data && q.data.length === 100 && (
        <Button onClick={() => setBefore(q.data[q.data.length - 1].seq)}>Older events</Button>
      )}
    </div>
  );
}

function Jobs() {
  const [state, setState] = useState("");
  const toast = useToast();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["jobs", state], queryFn: () => get<Job[]>(`/api/v2/system/jobs${state ? `?state=${state}` : ""}`), refetchInterval: 5000 });
  const b = useQuery({ queryKey: ["breakers"], queryFn: () => get<{ key: string; state: string; failures: number; last_error: string; next_attempt: string }[]>("/api/v2/system/breakers"), refetchInterval: 10000 });
  const reset = async (key: string) => {
    try {
      await del(`/api/v2/system/breakers/${encodeURIComponent(key)}`);
      qc.invalidateQueries({ queryKey: ["breakers"] });
      toast("green", "Circuit breaker reset");
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };
  const open = (b.data ?? []).filter((x) => x.state !== "closed");
  return (
    <div className="space-y-6">
      {open.length > 0 && (
        <Card title="Open circuit breakers" padded={false}>
          <ul className="divide-y divide-zinc-800">
            {open.map((x) => (
              <li key={x.key} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm">
                <div className="min-w-0">
                  <p className="font-mono text-zinc-100">{x.key}</p>
                  <p className="truncate text-xs text-red-300">
                    {x.failures} failures · {x.last_error}
                  </p>
                </div>
                <Button size="sm" onClick={() => reset(x.key)}>
                  Reset
                </Button>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <div className="space-y-3">
        <Select value={state} onChange={(e) => setState(e.target.value)} className="w-48">
          <option value="">All states</option>
          <option value="queued">Queued</option>
          <option value="running">Running</option>
          <option value="dead">Dead</option>
        </Select>
        <Card padded={false}>
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-900 text-zinc-500">
              <tr>
                <th className="px-3 py-2">Kind</th>
                <th className="px-3 py-2">Key</th>
                <th className="px-3 py-2">State</th>
                <th className="px-3 py-2">Attempts</th>
                <th className="px-3 py-2">Last error</th>
                <th className="px-3 py-2">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {q.data?.map((j) => (
                <tr key={j.id}>
                  <td className="px-3 py-2 font-mono">{j.kind}</td>
                  <td className="max-w-xs truncate px-3 py-2 text-zinc-400">{j.idempotency_key}</td>
                  <td className="px-3 py-2">
                    <Badge tone={j.state === "dead" ? "red" : j.state === "done" ? "green" : "blue"}>{j.state}</Badge>
                  </td>
                  <td className="px-3 py-2">
                    {j.attempts}/{j.max_attempts}
                  </td>
                  <td className="max-w-md truncate px-3 py-2 text-red-300" title={j.last_error}>
                    {j.last_error}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-zinc-500">{timeAgo(j.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}
