import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { errorMessage, get, post } from "../api/client";
import type { BuildOverrides, Deployment, GitStatus, Plan, Project, Repo } from "../api/types";
import { useAuth } from "../auth";
import { EnvEditor, type EnvRow } from "../components/EnvEditor";
import { Alert, Badge, Button, Card, Code, EmptyState, Field, Input, Loading, PageHeader, Select, Tabs, Textarea, Toggle } from "../components/ui";

type Source = { kind: "github"; repo: Repo } | { kind: "git"; url: string };

export function NewProjectPage() {
  const [source, setSource] = useState<Source | null>(null);
  return (
    <>
      <PageHeader title="Import project" subtitle="Deploy from a GitHub repository or any public Git URL." />
      {!source ? <SourcePicker onPick={setSource} /> : <Configure source={source} onBack={() => setSource(null)} />}
    </>
  );
}

function SourcePicker({ onPick }: { onPick: (s: Source) => void }) {
  const [tab, setTab] = useState<"github" | "git">("github");
  const { user } = useAuth();
  const git = useQuery({ queryKey: ["git"], queryFn: () => get<GitStatus>("/api/v2/git") });
  const repos = useQuery({
    queryKey: ["repos"],
    queryFn: () => get<Repo[]>("/api/v2/git/repositories"),
    enabled: !!git.data?.configured && (git.data?.connections.length ?? 0) > 0,
  });
  const [filter, setFilter] = useState("");
  const [url, setUrl] = useState("");
  const shown = useMemo(() => (repos.data ?? []).filter((r) => r.full_name.toLowerCase().includes(filter.toLowerCase())), [repos.data, filter]);

  return (
    <Card>
      <Tabs
        tabs={[
          { id: "github", label: "GitHub" },
          { id: "git", label: "Public Git URL" },
        ]}
        value={tab}
        onChange={setTab}
      />
      {tab === "github" && (
        <div className="space-y-4">
          {git.isLoading && <Loading />}
          {git.data && !git.data.configured && (
            <EmptyState
              title="GitHub is not connected"
              action={
                user?.role === "owner" ? (
                  <Link to="/settings/github">
                    <Button variant="primary">Connect GitHub</Button>
                  </Link>
                ) : undefined
              }
            >
              An owner registers a private GitHub App for this node. Repository access is scoped per installation and tokens are short-lived.
            </EmptyState>
          )}
          {git.data?.configured && git.data.connections.length === 0 && (
            <EmptyState
              title="Install the GitHub App"
              action={
                git.data.install_url && (
                  <a href={git.data.install_url} rel="noreferrer">
                    <Button variant="primary">Install on GitHub</Button>
                  </a>
                )
              }
            >
              Choose which repositories OpenDeploy may read. You can change this later on GitHub.
            </EmptyState>
          )}
          {repos.data && (
            <>
              <div className="flex gap-2">
                <Input placeholder="Search repositories" value={filter} onChange={(e) => setFilter(e.target.value)} />
                {git.data?.install_url && (
                  <a href={git.data.install_url} rel="noreferrer">
                    <Button>Adjust access</Button>
                  </a>
                )}
              </div>
              <ul className="divide-y divide-zinc-800 rounded-md border border-zinc-800">
                {shown.map((r) => (
                  <li key={`${r.connection_id}/${r.id}`} className="flex items-center justify-between gap-3 px-3 py-2.5">
                    <div className="min-w-0">
                      <p className="truncate text-sm text-zinc-100">{r.full_name}</p>
                      <p className="text-xs text-zinc-500">
                        {r.private ? "private" : "public"} · {r.default_branch}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      {r.imported && <Badge>imported</Badge>}
                      <Button size="sm" variant="primary" onClick={() => onPick({ kind: "github", repo: r })}>
                        Import
                      </Button>
                    </div>
                  </li>
                ))}
                {shown.length === 0 && <li className="px-3 py-6 text-center text-sm text-zinc-500">No repositories match.</li>}
              </ul>
            </>
          )}
          {repos.error && <Alert>{errorMessage(repos.error)}</Alert>}
        </div>
      )}
      {tab === "git" && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            onPick({ kind: "git", url: url.trim() });
          }}
        >
          <Field label="Repository URL" hint="HTTPS URL of a public repository. Private repositories require the GitHub App.">
            <Input required type="url" placeholder="https://github.com/owner/repo.git" value={url} onChange={(e) => setUrl(e.target.value)} />
          </Field>
          <Button type="submit" variant="primary" disabled={!/^https:\/\//.test(url.trim())}>
            Continue
          </Button>
        </form>
      )}
    </Card>
  );
}

function slug(s: string) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

function Configure({ source, onBack }: { source: Source; onBack: () => void }) {
  const nav = useNavigate();
  const repoName = source.kind === "github" ? source.repo.full_name.split("/")[1] : (source.url.split("/").pop() ?? "app").replace(/\.git$/, "");
  const [name, setName] = useState(slug(repoName));
  const [branch, setBranch] = useState(source.kind === "github" ? source.repo.default_branch : "main");
  const [rootDir, setRootDir] = useState(".");
  const [build, setBuild] = useState<BuildOverrides>({ strategy: "auto" });
  const [env, setEnv] = useState<EnvRow[]>([]);
  const [trust, setTrust] = useState<"trusted" | "untrusted">("trusted");
  const [previews, setPreviews] = useState(false);
  const [autoDeploy, setAutoDeploy] = useState(true);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [planning, setPlanning] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const branches = useQuery({
    queryKey: ["branches", source.kind === "github" ? source.repo.id : 0],
    queryFn: () => get<{ default: string; branches: string[] }>(`/api/v2/git/repositories/${source.kind === "github" ? source.repo.connection_id : ""}/${source.kind === "github" ? source.repo.id : 0}/branches`),
    enabled: source.kind === "github",
  });

  const srcBody = source.kind === "github" ? { git_connection_id: source.repo.connection_id, repo_id: source.repo.id } : { clone_url: source.url };
  const cleanBuild = (): BuildOverrides => {
    const b: BuildOverrides = { ...build };
    if (b.strategy === "auto") delete b.strategy;
    (Object.keys(b) as (keyof BuildOverrides)[]).forEach((k) => (b[k] === "" || b[k] === 0) && delete b[k]);
    return b;
  };

  const detect = async () => {
    setPlanning(true);
    setErr("");
    try {
      setPlan(await post<Plan>("/api/v2/projects/plan", { ...srcBody, branch, root_dir: rootDir, build: cleanBuild() }));
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setPlanning(false);
    }
  };

  const create = async () => {
    setBusy(true);
    setErr("");
    try {
      const envMap: Record<string, string> = {};
      env.filter((r) => r.key).forEach((r) => (envMap[r.key] = r.value));
      const r = await post<{ project: Project; deployment?: Deployment }>("/api/v2/projects", {
        ...srcBody,
        name,
        production_branch: branch,
        root_dir: rootDir,
        trust_class: trust,
        previews_enabled: previews,
        auto_deploy: autoDeploy,
        build: cleanBuild(),
        env: envMap,
      });
      nav(r.deployment ? `/deployments/${r.deployment.id}` : `/projects/${r.project.id}`);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_380px]">
      <div className="space-y-6">
        <Card
          title={
            <span>
              Configure <span className="text-zinc-400">{source.kind === "github" ? source.repo.full_name : source.url}</span>
            </span>
          }
          actions={
            <Button size="sm" variant="ghost" onClick={onBack}>
              Change source
            </Button>
          }
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Project name" hint="Lowercase letters, digits and dashes. Used in the generated URL.">
              <Input value={name} onChange={(e) => setName(slug(e.target.value))} />
            </Field>
            <Field label="Production branch">
              {branches.data ? (
                <Select value={branch} onChange={(e) => setBranch(e.target.value)}>
                  {branches.data.branches.map((b) => (
                    <option key={b}>{b}</option>
                  ))}
                </Select>
              ) : (
                <Input value={branch} onChange={(e) => setBranch(e.target.value)} />
              )}
            </Field>
            <Field label="Root directory" hint="For monorepos: the app's folder relative to the repository root.">
              <Input value={rootDir} onChange={(e) => setRootDir(e.target.value)} />
            </Field>
            <Field label="Build strategy">
              <Select value={build.strategy ?? "auto"} onChange={(e) => setBuild({ ...build, strategy: e.target.value })}>
                <option value="auto">Auto-detect</option>
                <option value="dockerfile">Dockerfile</option>
                <option value="static">Static site</option>
                <option value="buildpacks">Cloud Native Buildpacks</option>
                <option value="nixpacks">Nixpacks</option>
              </Select>
            </Field>
            <Field label="Build command" hint="Optional override">
              <Input className="font-mono" value={build.build_command ?? ""} onChange={(e) => setBuild({ ...build, build_command: e.target.value })} />
            </Field>
            <Field label="Start command" hint="Optional override">
              <Input className="font-mono" value={build.start_command ?? ""} onChange={(e) => setBuild({ ...build, start_command: e.target.value })} />
            </Field>
            <Field label="Output directory" hint="Static sites: build output folder">
              <Input className="font-mono" value={build.output_dir ?? ""} onChange={(e) => setBuild({ ...build, output_dir: e.target.value })} />
            </Field>
            <Field label="Port" hint="Leave empty to use the detected port">
              <Input type="number" min={1} max={65535} value={build.port || ""} onChange={(e) => setBuild({ ...build, port: Number(e.target.value) || 0 })} />
            </Field>
          </div>
          <div className="mt-4">
            <Button onClick={detect} loading={planning}>
              Preview detection
            </Button>
          </div>
        </Card>

        <Card title="Environment variables">
          <p className="mb-3 text-xs text-zinc-500">Stored encrypted for the production environment. Values are never shown again in lists.</p>
          <EnvEditor rows={env} onChange={setEnv} />
        </Card>

        <Card title="Security & automation">
          <div className="space-y-4">
            <Field label="Trust class" hint="Untrusted code builds and runs in the gVisor sandbox; if the host lacks it, deployments fail closed.">
              <Select value={trust} onChange={(e) => setTrust(e.target.value as "trusted" | "untrusted")}>
                <option value="trusted">Trusted — your own code</option>
                <option value="untrusted">Untrusted — third-party code, maximum isolation</option>
              </Select>
            </Field>
            <Toggle checked={autoDeploy} onChange={setAutoDeploy} label="Deploy on push" description={`Push to ${branch} deploys production automatically.`} />
            <Toggle checked={previews} onChange={setPreviews} label="Pull request previews" description="Each PR gets its own URL. Previews from forks stay disabled unless you allow them in settings." />
          </div>
        </Card>
      </div>

      <div className="space-y-4">
        <Card title="Detection">
          {!plan && !planning && <p className="text-sm text-zinc-500">Run a preview to see how OpenDeploy will build this project.</p>}
          {planning && <Loading label="Fetching and analysing source…" />}
          {plan && <PlanView plan={plan} />}
        </Card>
        {err && <Alert>{err}</Alert>}
        <Button variant="primary" className="w-full" loading={busy} disabled={!name} onClick={create}>
          Deploy
        </Button>
      </div>
    </div>
  );
}

export function PlanView({ plan }: { plan: Plan }) {
  const [showDf, setShowDf] = useState(false);
  if (plan.error) return <Alert title="Detection failed">{plan.error}</Alert>;
  const p = plan.plan;
  return (
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap gap-2">
        <Badge tone="indigo">{p.stack}</Badge>
        {p.framework && <Badge tone="blue">{p.framework}</Badge>}
        <Badge>{p.strategy}</Badge>
        {p.static_output ? <Badge tone="green">static</Badge> : <Badge>port {p.port}</Badge>}
      </div>
      {plan.commit?.sha && (
        <p className="text-xs text-zinc-500">
          Commit <Code>{plan.commit.sha.slice(0, 7)}</Code>
        </p>
      )}
      <dl className="space-y-1 text-xs">
        {p.build_command && (
          <div>
            <dt className="text-zinc-500">Build</dt>
            <dd className="font-mono text-zinc-300">{p.build_command}</dd>
          </div>
        )}
        {p.start_command && (
          <div>
            <dt className="text-zinc-500">Start</dt>
            <dd className="font-mono text-zinc-300">{p.start_command}</dd>
          </div>
        )}
      </dl>
      <ul className="list-inside list-disc space-y-0.5 text-xs text-zinc-400">
        {p.reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
      {p.warnings?.map((w) => (
        <Alert key={w} tone="amber">
          {w}
        </Alert>
      ))}
      {plan.dockerfile && (
        <div>
          <button className="text-xs text-indigo-300 hover:text-indigo-200" onClick={() => setShowDf(!showDf)}>
            {showDf ? "Hide" : "Show"} generated Dockerfile
          </button>
          {showDf && <Textarea readOnly rows={14} value={plan.dockerfile} className="mt-2 text-xs" />}
        </div>
      )}
    </div>
  );
}
