import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get } from "../api/client";
import type { ProjectView } from "../api/types";
import { Alert, Badge, Button, EmptyState, Loading, PageHeader, StatusBadge } from "../components/ui";
import { shortSha, timeAgo } from "../lib/format";
import { errorMessage } from "../api/client";

export function ProjectsPage() {
  const q = useQuery({ queryKey: ["projects"], queryFn: () => get<ProjectView[]>("/api/v2/projects"), refetchInterval: 10_000 });
  return (
    <>
      <PageHeader
        title="Projects"
        subtitle="Git-connected apps running on this node."
        actions={
          <Link to="/new">
            <Button variant="primary">Import project</Button>
          </Link>
        }
      />
      {q.isLoading && <Loading />}
      {q.error && <Alert>{errorMessage(q.error)}</Alert>}
      {q.data && q.data.length === 0 && (
        <EmptyState
          title="No projects yet"
          action={
            <Link to="/new">
              <Button variant="primary">Import your first project</Button>
            </Link>
          }
        >
          Connect GitHub or paste a public repository URL. OpenDeploy detects the stack, builds an immutable image and publishes a URL.
        </EmptyState>
      )}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {q.data?.map((p) => {
          const latest = p.production?.latest_deployment;
          return (
            <Link key={p.id} to={`/projects/${p.id}`} className="group rounded-lg border border-zinc-800 bg-zinc-900/60 p-4 transition-colors hover:border-zinc-700">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate font-medium text-white group-hover:text-indigo-300">{p.name}</p>
                  <p className="truncate text-xs text-zinc-500">{p.repo_full_name || (p.source_kind === "upload" ? "CLI uploads" : "")}</p>
                </div>
                {latest ? <StatusBadge status={latest.status} /> : <Badge>No deployments</Badge>}
              </div>
              {p.url && <p className="mt-3 truncate text-sm text-indigo-300">{p.url.replace(/^https?:\/\//, "")}</p>}
              {latest && (
                <p className="mt-3 truncate text-xs text-zinc-400">
                  {latest.commit_message ? latest.commit_message.split("\n")[0] : latest.trigger} {latest.commit_sha && <span className="font-mono text-zinc-500">· {shortSha(latest.commit_sha)}</span>}
                </p>
              )}
              <div className="mt-3 flex items-center gap-2 text-xs text-zinc-500">
                <span>{p.production_branch}</span>
                <span>·</span>
                <span>{timeAgo(latest?.created_at ?? p.created_at)}</span>
                {p.trust_class !== "trusted" && <Badge tone={p.trust_class === "privileged" ? "red" : "amber"}>{p.trust_class}</Badge>}
              </div>
            </Link>
          );
        })}
      </div>
    </>
  );
}
