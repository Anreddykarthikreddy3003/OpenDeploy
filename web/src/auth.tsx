import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, errorMessage, get, onAuthError, post, setCsrf, setReauthHandler } from "./api/client";
import type { SessionInfo, User } from "./api/types";
import { Alert, Button, Field, Input, Modal } from "./components/ui";
import { getAssertion, webauthnSupported } from "./lib/webauthn";

type AuthState =
  | { phase: "loading" }
  | { phase: "bootstrap" }
  | { phase: "anonymous" }
  | { phase: "mfa"; session: SessionInfo }
  | { phase: "enroll"; session: SessionInfo }
  | { phase: "ready"; session: SessionInfo };

interface AuthCtx {
  state: AuthState;
  user?: User;
  refresh: () => Promise<void>;
  accept: (s: SessionInfo) => void;
  logout: () => Promise<void>;
  requireMFA: boolean;
}

const Ctx = createContext<AuthCtx>(null as any);
export const useAuth = () => useContext(Ctx);

function phaseFor(s: SessionInfo): AuthState {
  if (s.mfa_required) return { phase: "mfa", session: s };
  if (s.mfa_enrollment_required) return { phase: "enroll", session: s };
  return { phase: "ready", session: s };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ phase: "loading" });
  const [requireMFA, setRequireMFA] = useState(false);

  const accept = useCallback((s: SessionInfo) => {
    setCsrf(s.csrf_token);
    setState(phaseFor(s));
  }, []);

  const refresh = useCallback(async () => {
    try {
      const setup = await get<{ needs_bootstrap: boolean; require_mfa: boolean }>("/api/v2/setup");
      setRequireMFA(setup.require_mfa);
      if (setup.needs_bootstrap) {
        setState({ phase: "bootstrap" });
        return;
      }
      const me = await get<SessionInfo>("/api/v2/auth/me");
      accept(me);
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.code === "unauthorized")) {
        setCsrf("");
        setState({ phase: "anonymous" });
      } else {
        setState({ phase: "anonymous" });
      }
    }
  }, [accept]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(
    () =>
      onAuthError((e) => {
        if (e.code === "mfa_required" || e.code === "mfa_enrollment_required") void refresh();
        else if (e.code === "unauthorized") {
          setCsrf("");
          setState({ phase: "anonymous" });
        }
      }),
    [refresh],
  );

  const logout = useCallback(async () => {
    try {
      await post("/api/v2/auth/logout");
    } catch {
      /* already gone */
    }
    setCsrf("");
    setState({ phase: "anonymous" });
  }, []);

  const user = state.phase === "ready" || state.phase === "mfa" || state.phase === "enroll" ? state.session.user : undefined;
  return (
    <Ctx.Provider value={{ state, user, refresh, accept, logout, requireMFA }}>
      {children}
      {state.phase === "ready" && <ReauthDialog user={state.session.user} />}
    </Ctx.Provider>
  );
}

/** Prompts for password (+ second factor) when the API demands recent re-auth. */
function ReauthDialog({ user }: { user: User }) {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const resolver = useRef<((ok: boolean) => void) | null>(null);

  useEffect(() => {
    setReauthHandler(
      () =>
        new Promise<boolean>((resolve) => {
          resolver.current = resolve;
          setPassword("");
          setCode("");
          setErr("");
          setOpen(true);
        }),
    );
    return () => setReauthHandler(null);
  }, []);

  const finish = (ok: boolean) => {
    setOpen(false);
    resolver.current?.(ok);
    resolver.current = null;
  };

  const submit = async (useKey: boolean) => {
    setBusy(true);
    setErr("");
    try {
      const body: any = { password };
      if (useKey) {
        const opts = await post("/api/v2/auth/webauthn/login/begin");
        body.webauthn = await getAssertion(opts);
      } else if (user.totp_enabled) {
        body.code = code;
      }
      await post("/api/v2/auth/reauth", body);
      finish(true);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const keyOnly = user.webauthn_count > 0 && !user.totp_enabled;
  return (
    <Modal
      open={open}
      onClose={() => finish(false)}
      title="Confirm it's you"
      footer={
        <>
          <Button variant="ghost" onClick={() => finish(false)}>
            Cancel
          </Button>
          {user.webauthn_count > 0 && webauthnSupported() && (
            <Button variant={keyOnly ? "primary" : "secondary"} loading={busy} onClick={() => submit(true)} disabled={!password}>
              Use security key
            </Button>
          )}
          {!keyOnly && (
            <Button variant="primary" loading={busy} onClick={() => submit(false)} disabled={!password || (user.totp_enabled && code.length < 6)}>
              Confirm
            </Button>
          )}
        </>
      }
    >
      <p className="text-sm text-zinc-400">This action is sensitive. Re-enter your password{user.totp_enabled || user.webauthn_count > 0 ? " and second factor" : ""} to continue for the next few minutes.</p>
      {err && <Alert>{err}</Alert>}
      <Field label="Password">
        <Input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      {user.totp_enabled && (
        <Field label="Authenticator code">
          <Input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} placeholder="123456" />
        </Field>
      )}
    </Modal>
  );
}
