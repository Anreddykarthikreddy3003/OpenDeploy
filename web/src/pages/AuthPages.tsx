import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import QRCode from "qrcode";
import { errorMessage, post } from "../api/client";
import type { SessionInfo } from "../api/types";
import { useAuth } from "../auth";
import { Alert, Button, Code, CopyButton, Field, Input } from "../components/ui";
import { createCredential, getAssertion, webauthnSupported } from "../lib/webauthn";

function Shell({ title, subtitle, children }: { title: string; subtitle?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-2">
          <img src="/favicon.svg" alt="" className="h-8 w-8" />
          <span className="text-lg font-semibold text-white">OpenDeploy</span>
        </div>
        <h1 className="text-xl font-semibold text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-zinc-400">{subtitle}</p>}
        <div className="mt-6">{children}</div>
      </div>
    </div>
  );
}

export function SetupPage() {
  const { accept } = useAuth();
  const [f, setF] = useState({ token: "", name: "", email: "", password: "", confirm: "" });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (f.password !== f.confirm) return setErr("Passwords do not match");
    setBusy(true);
    setErr("");
    try {
      accept(await post<SessionInfo>("/api/v2/auth/bootstrap", { token: f.token.trim(), name: f.name, email: f.email, password: f.password }));
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Shell
      title="Create the owner account"
      subtitle={
        <>
          Paste the one-time bootstrap token printed by <Code>opendeployctl admin bootstrap-token</Code> (or found in the platform data directory).
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4">
        {err && <Alert>{err}</Alert>}
        <Field label="Bootstrap token">
          <Input required value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Name">
          <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} autoComplete="name" />
        </Field>
        <Field label="Email">
          <Input required type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} autoComplete="email" />
        </Field>
        <Field label="Password" hint="At least 12 characters. A passphrase is best.">
          <Input required type="password" minLength={12} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" />
        </Field>
        <Field label="Confirm password">
          <Input required type="password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} autoComplete="new-password" />
        </Field>
        <Button type="submit" variant="primary" loading={busy} className="w-full">
          Create owner
        </Button>
      </form>
    </Shell>
  );
}

export function LoginPage() {
  const { accept } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      accept(await post<SessionInfo>("/api/v2/auth/login", { email, password }));
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Shell title="Sign in">
      <form onSubmit={submit} className="space-y-4">
        {err && <Alert>{err}</Alert>}
        <Field label="Email">
          <Input required type="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
        </Field>
        <Field label="Password">
          <Input required type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        </Field>
        <Button type="submit" variant="primary" loading={busy} className="w-full">
          Sign in
        </Button>
      </form>
    </Shell>
  );
}

export function MFAPage({ session }: { session: SessionInfo }) {
  const { accept, logout } = useAuth();
  const methods = session.mfa_methods ?? [];
  const [mode, setMode] = useState<"totp" | "recovery">("totp");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const key = methods.includes("webauthn") && webauthnSupported();

  const useKey = async () => {
    setBusy(true);
    setErr("");
    try {
      const opts = await post("/api/v2/auth/webauthn/login/begin");
      accept(await post<SessionInfo>("/api/v2/auth/webauthn/login/finish", await getAssertion(opts)));
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    if (key && !methods.includes("totp")) void useKey();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      accept(await post<SessionInfo>("/api/v2/auth/mfa", mode === "totp" ? { code } : { recovery_code: code.trim() }));
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Shell title="Two-factor verification" subtitle={`Signed in as ${session.user.email}`}>
      <div className="space-y-4">
        {err && <Alert>{err}</Alert>}
        {key && (
          <Button variant="primary" className="w-full" loading={busy} onClick={useKey}>
            Use security key
          </Button>
        )}
        {(methods.includes("totp") || mode === "recovery") && (
          <form onSubmit={submit} className="space-y-4">
            <Field label={mode === "totp" ? "Authenticator code" : "Recovery code"}>
              <Input
                autoFocus={!key}
                inputMode={mode === "totp" ? "numeric" : "text"}
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(mode === "totp" ? e.target.value.replace(/\D/g, "").slice(0, 6) : e.target.value)}
              />
            </Field>
            <Button type="submit" variant={key ? "secondary" : "primary"} loading={busy} className="w-full">
              Verify
            </Button>
          </form>
        )}
        <div className="flex justify-between text-xs">
          <button className="text-zinc-400 hover:text-white" onClick={() => setMode(mode === "totp" ? "recovery" : "totp")}>
            {mode === "totp" ? "Use a recovery code" : methods.includes("totp") ? "Use authenticator code" : "Back"}
          </button>
          <button className="text-zinc-400 hover:text-white" onClick={logout}>
            Sign out
          </button>
        </div>
      </div>
    </Shell>
  );
}

/** MFA enrollment: used both for mandatory first enrollment and from Account. */
export function EnrollMFA({ onDone, embedded }: { onDone: () => void; embedded?: boolean }) {
  const [totp, setTotp] = useState<{ secret: string; uri: string; qr: string } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [keyName, setKeyName] = useState("Security key");

  const startTOTP = async () => {
    setErr("");
    try {
      const r = await post<{ secret: string; uri: string }>("/api/v2/auth/totp/enroll");
      setTotp({ ...r, qr: await QRCode.toDataURL(r.uri, { margin: 1, width: 200 }) });
    } catch (e) {
      setErr(errorMessage(e));
    }
  };
  const confirmTOTP = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const r = await post<{ recovery_codes: string[] }>("/api/v2/auth/totp/confirm", { code });
      setCodes(r.recovery_codes);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const addKey = async () => {
    setBusy(true);
    setErr("");
    try {
      const opts = await post("/api/v2/auth/webauthn/register/begin");
      const cred = await createCredential(opts);
      const r = await post<{ recovery_codes?: string[] }>("/api/v2/auth/webauthn/register/finish", { name: keyName, credential: cred });
      if (r.recovery_codes) setCodes(r.recovery_codes);
      else onDone();
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  if (codes) {
    return (
      <div className="space-y-4">
        <Alert tone="amber" title="Save your recovery codes">
          Each code works once if you lose your second factor. They will not be shown again.
        </Alert>
        <div className="grid grid-cols-2 gap-2 rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-sm">
          {codes.map((c) => (
            <span key={c}>{c}</span>
          ))}
        </div>
        <div className="flex gap-2">
          <CopyButton value={codes.join("\n")} label="Copy codes" />
          <Button variant="primary" onClick={onDone}>
            I saved them
          </Button>
        </div>
      </div>
    );
  }
  return (
    <div className="space-y-5">
      {err && <Alert>{err}</Alert>}
      {webauthnSupported() && (
        <div className={embedded ? "" : "rounded-lg border border-zinc-800 p-4"}>
          <p className="text-sm font-medium text-zinc-100">Security key or passkey</p>
          <p className="mt-1 text-xs text-zinc-500">Phishing-resistant. Recommended.</p>
          <div className="mt-3 flex gap-2">
            <Input value={keyName} onChange={(e) => setKeyName(e.target.value)} className="max-w-48" aria-label="Key name" />
            <Button variant="primary" loading={busy && !totp} onClick={addKey}>
              Register key
            </Button>
          </div>
        </div>
      )}
      <div className={embedded ? "" : "rounded-lg border border-zinc-800 p-4"}>
        <p className="text-sm font-medium text-zinc-100">Authenticator app (TOTP)</p>
        {!totp ? (
          <Button className="mt-3" onClick={startTOTP}>
            Set up authenticator app
          </Button>
        ) : (
          <form onSubmit={confirmTOTP} className="mt-3 space-y-3">
            <img src={totp.qr} alt="TOTP QR code" className="rounded bg-white p-1" width={180} height={180} />
            <p className="text-xs text-zinc-500">
              Or enter the key manually: <Code>{totp.secret}</Code>
            </p>
            <Field label="Code from the app">
              <Input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} />
            </Field>
            <Button type="submit" variant="primary" loading={busy} disabled={code.length !== 6}>
              Verify and enable
            </Button>
          </form>
        )}
      </div>
    </div>
  );
}

export function EnrollPage() {
  const { refresh, logout, state } = useAuth();
  const email = state.phase === "enroll" ? state.session.user.email : "";
  return (
    <Shell title="Protect your account" subtitle={`Your role requires a second factor before you can continue (${email}).`}>
      <EnrollMFA onDone={refresh} />
      <button className="mt-6 text-xs text-zinc-400 hover:text-white" onClick={logout}>
        Sign out
      </button>
    </Shell>
  );
}
