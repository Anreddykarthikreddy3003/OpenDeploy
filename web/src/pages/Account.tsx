import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { del, errorMessage, get, post } from "../api/client";
import type { APIToken, Session } from "../api/types";
import { useAuth } from "../auth";
import { Alert, Badge, Button, Card, CopyButton, Field, Input, Modal, PageHeader, Select, useToast } from "../components/ui";
import { formatDate, timeAgo } from "../lib/format";
import { EnrollMFA } from "./AuthPages";

export function AccountPage() {
  const { user, refresh } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const keys = useQuery({ queryKey: ["webauthn"], queryFn: () => get<{ id: string; name: string; created_at: string; last_used_at: string }[]>("/api/v2/auth/webauthn/credentials") });
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: () => get<Session[]>("/api/v2/auth/sessions") });
  const tokens = useQuery({ queryKey: ["tokens"], queryFn: () => get<APIToken[]>("/api/v2/auth/tokens") });
  const [enroll, setEnroll] = useState(false);
  const [newTok, setNewTok] = useState({ name: "", role: "developer", days: 90 });
  const [created, setCreated] = useState("");

  const run = async (fn: () => Promise<any>, ok?: string) => {
    try {
      await fn();
      if (ok) toast("green", ok);
      await refresh();
      qc.invalidateQueries();
    } catch (e) {
      toast("red", errorMessage(e));
    }
  };

  return (
    <>
      <PageHeader title="Account" subtitle={`${user?.email} · ${user?.role}`} />
      <div className="space-y-6">
        <Card title="Two-factor authentication" actions={<Button size="sm" variant="primary" onClick={() => setEnroll(true)}>Add factor</Button>}>
          <ul className="space-y-2 text-sm">
            <li className="flex items-center justify-between">
              <span>Authenticator app</span>
              {user?.totp_enabled ? (
                <span className="flex items-center gap-2">
                  <Badge tone="green">enabled</Badge>
                  <Button size="sm" variant="ghost" onClick={() => run(() => del("/api/v2/auth/totp"), "Authenticator app removed")}>
                    Remove
                  </Button>
                </span>
              ) : (
                <Badge>off</Badge>
              )}
            </li>
            {keys.data?.map((k) => (
              <li key={k.id} className="flex items-center justify-between">
                <span>
                  {k.name} <span className="text-xs text-zinc-500">· added {timeAgo(k.created_at)}{k.last_used_at && ` · used ${timeAgo(k.last_used_at)}`}</span>
                </span>
                <Button size="sm" variant="ghost" onClick={() => run(() => del(`/api/v2/auth/webauthn/credentials/${k.id}`), "Security key removed")}>
                  Remove
                </Button>
              </li>
            ))}
            {!user?.totp_enabled && !keys.data?.length && <Alert tone="amber">No second factor. Add a security key or authenticator app.</Alert>}
          </ul>
        </Card>

        <Card title="Sessions" actions={<Button size="sm" onClick={() => run(() => post("/api/v2/auth/sessions/revoke-others"), "Other sessions signed out")}>Sign out other sessions</Button>} padded={false}>
          <ul className="divide-y divide-zinc-800">
            {sessions.data?.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm">
                <div className="min-w-0">
                  <p className="truncate text-zinc-200">
                    {s.user_agent || "Unknown client"} {s.current && <Badge tone="indigo">this session</Badge>}
                  </p>
                  <p className="text-xs text-zinc-500">
                    {s.source_ip} · signed in {formatDate(s.created_at)} · active {timeAgo(s.last_seen_at)} {s.mfa ? "· MFA" : ""}
                  </p>
                </div>
                {!s.current && (
                  <Button size="sm" variant="ghost" onClick={() => run(() => del(`/api/v2/auth/sessions/${s.id}`))}>
                    Revoke
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </Card>

        <Card title="API tokens" padded={false}>
          <p className="px-4 pt-3 text-xs text-zinc-500">For the CLI and CI. A token's role is capped at your own and it cannot perform actions that need re-authentication.</p>
          <ul className="divide-y divide-zinc-800">
            {tokens.data?.map((t) => (
              <li key={t.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
                <div>
                  <p className="text-zinc-200">
                    {t.name} <Badge>{t.role_cap}</Badge>
                  </p>
                  <p className="text-xs text-zinc-500">
                    expires {formatDate(t.expires_at)} {t.last_used_at && `· used ${timeAgo(t.last_used_at)}`}
                  </p>
                </div>
                <Button size="sm" variant="ghost" onClick={() => run(() => del(`/api/v2/auth/tokens/${t.id}`), "Token revoked")}>
                  Revoke
                </Button>
              </li>
            ))}
          </ul>
          <form
            className="flex flex-wrap gap-2 border-t border-zinc-800 p-4"
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                const r = await post<{ token: string }>("/api/v2/auth/tokens", { name: newTok.name, role: newTok.role, expires_in_days: newTok.days });
                setCreated(r.token);
                setNewTok({ ...newTok, name: "" });
                qc.invalidateQueries({ queryKey: ["tokens"] });
              } catch (err) {
                toast("red", errorMessage(err));
              }
            }}
          >
            <Input placeholder="Token name" value={newTok.name} onChange={(e) => setNewTok({ ...newTok, name: e.target.value })} className="max-w-xs flex-1" />
            <Select value={newTok.role} onChange={(e) => setNewTok({ ...newTok, role: e.target.value })} className="w-36">
              <option value="viewer">Viewer</option>
              <option value="developer">Developer</option>
              <option value="admin">Admin</option>
            </Select>
            <Select value={String(newTok.days)} onChange={(e) => setNewTok({ ...newTok, days: Number(e.target.value) })} className="w-32">
              <option value="7">7 days</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="365">1 year</option>
            </Select>
            <Button type="submit" disabled={!newTok.name}>
              Create token
            </Button>
          </form>
        </Card>
      </div>

      <Modal open={enroll} onClose={() => setEnroll(false)} title="Add a second factor" wide>
        <EnrollMFA
          embedded
          onDone={() => {
            setEnroll(false);
            void refresh();
            qc.invalidateQueries({ queryKey: ["webauthn"] });
          }}
        />
      </Modal>
      <Modal open={!!created} onClose={() => setCreated("")} title="New API token" footer={<Button onClick={() => setCreated("")}>Done</Button>}>
        <Alert tone="amber">Copy it now — it will not be shown again.</Alert>
        <Field label="Token">
          <div className="flex gap-2">
            <Input readOnly value={created} className="font-mono" />
            <CopyButton value={created} />
          </div>
        </Field>
      </Modal>
    </>
  );
}
