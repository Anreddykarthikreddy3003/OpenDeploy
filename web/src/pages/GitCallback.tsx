import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { errorMessage, post } from "../api/client";
import { Alert, Button, Card, Loading, PageHeader } from "../components/ui";

// GitHub redirects here after the App manifest is confirmed. The code is
// exchanged by an authenticated same-origin POST (the state is bound to the
// user who started the flow).
export function GitCallbackPage() {
  const [params] = useSearchParams();
  const [res, setRes] = useState<{ name: string; install_url: string } | null>(null);
  const [err, setErr] = useState("");
  const once = useRef(false);
  useEffect(() => {
    if (once.current) return;
    once.current = true;
    const code = params.get("code");
    const state = params.get("state");
    if (!code || !state) {
      setErr("Missing code or state from GitHub.");
      return;
    }
    post<{ name: string; install_url: string }>("/api/v2/git/github/manifest/complete", { code, state })
      .then(setRes)
      .catch((e) => setErr(errorMessage(e)));
  }, [params]);
  return (
    <>
      <PageHeader title="Connect GitHub" />
      <Card>
        {!res && !err && <Loading label="Finishing GitHub App registration…" />}
        {err && <Alert title="Registration failed">{err}</Alert>}
        {res && (
          <div className="space-y-4">
            <Alert tone="green" title={`GitHub App "${res.name}" created`}>
              Its private key and webhook secret are stored encrypted by secretd.
            </Alert>
            <p className="text-sm text-zinc-400">Install the app on the accounts and repositories OpenDeploy should deploy.</p>
            <div className="flex gap-2">
              <a href={res.install_url} rel="noreferrer">
                <Button variant="primary">Install the app</Button>
              </a>
              <Link to="/settings/github">
                <Button>Back to settings</Button>
              </Link>
            </div>
          </div>
        )}
      </Card>
    </>
  );
}
