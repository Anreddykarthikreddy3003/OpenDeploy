import { createContext, useCallback, useContext, useEffect, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import type { DeploymentStatus } from "../api/types";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

type Variant = "primary" | "secondary" | "danger" | "ghost";
const variants: Record<Variant, string> = {
  primary: "bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-600/50",
  secondary: "bg-zinc-800 text-zinc-100 hover:bg-zinc-700 border border-zinc-700 disabled:opacity-50",
  danger: "bg-red-600 text-white hover:bg-red-500 disabled:bg-red-600/50",
  ghost: "text-zinc-300 hover:bg-zinc-800 hover:text-white disabled:opacity-50",
};

export function Button({ variant = "secondary", loading, className, children, size = "md", ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; loading?: boolean; size?: "sm" | "md" }) {
  return (
    <button
      {...rest}
      disabled={rest.disabled || loading}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 disabled:cursor-not-allowed",
        size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-2 text-sm",
        variants[variant],
        className,
      )}
    >
      {loading && <Spinner className="h-3.5 w-3.5" />}
      {children}
    </button>
  );
}

export function Spinner({ className = "h-4 w-4" }: { className?: string }) {
  return <span className={cx("inline-block animate-spin rounded-full border-2 border-current border-t-transparent", className)} aria-label="loading" />;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-8 text-sm text-zinc-400">
      <Spinner /> {label}
    </div>
  );
}

const inputCls = "rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-60";

// Width defaults to full unless the caller sets one (w-*, max-w-* or flex-1).
const widthOf = (c?: string) => (c && /(^|\s)(w-|max-w-|flex-1)/.test(c) ? "" : "w-full");

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx(inputCls, widthOf(props.className), props.className)} />;
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx(inputCls, widthOf(props.className), "font-mono", props.className)} />;
}

export function Select({ children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select {...props} className={cx(inputCls, widthOf(props.className), "pr-8", props.className)}>
      {children}
    </select>
  );
}

export function Field({ label, hint, children, error }: { label: string; hint?: ReactNode; children: ReactNode; error?: string }) {
  return (
    <div className="space-y-1.5">
      <label className="block space-y-1.5">
        <span className="block text-sm font-medium text-zinc-300">{label}</span>
        {children}
      </label>
      {hint && !error && <span className="block text-xs text-zinc-500">{hint}</span>}
      {error && <span className="block text-xs text-red-400" role="alert">{error}</span>}
    </div>
  );
}

export function Toggle({ checked, onChange, label, description, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; description?: ReactNode; disabled?: boolean }) {
  return (
    <label className={cx("flex cursor-pointer items-start justify-between gap-4", disabled && "cursor-not-allowed opacity-60")}>
      <span>
        <span className="block text-sm font-medium text-zinc-200">{label}</span>
        {description && <span className="mt-0.5 block text-xs text-zinc-500">{description}</span>}
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cx("relative mt-0.5 inline-flex h-5 w-9 shrink-0 rounded-full transition-colors", checked ? "bg-indigo-600" : "bg-zinc-700")}
      >
        <span className={cx("absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform", checked ? "translate-x-4" : "translate-x-0.5")} />
      </button>
    </label>
  );
}

export function Card({ title, actions, children, className, padded = true }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; padded?: boolean }) {
  return (
    <section className={cx("rounded-lg border border-zinc-800 bg-zinc-900/60", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-zinc-800 px-4 py-3">
          <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={padded ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-zinc-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

type Tone = "gray" | "green" | "red" | "amber" | "blue" | "indigo";
const tones: Record<Tone, string> = {
  gray: "bg-zinc-800 text-zinc-300 ring-zinc-700",
  green: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  red: "bg-red-500/10 text-red-300 ring-red-500/30",
  amber: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  blue: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
  indigo: "bg-indigo-500/10 text-indigo-300 ring-indigo-500/30",
};

export function Badge({ tone = "gray", children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return <span className={cx("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", tones[tone], className)}>{children}</span>;
}

export function statusTone(s: DeploymentStatus | string): Tone {
  switch (s) {
    case "SUCCEEDED":
    case "active":
    case "healthy":
    case "running":
      return "green";
    case "FAILED":
    case "failed":
    case "unhealthy":
    case "error":
      return "red";
    case "CANCELLED":
    case "SUPERSEDED":
    case "stopped":
    case "tombstoned":
    case "expired":
      return "gray";
    case "pending":
    case "issuing":
      return "amber";
    default:
      return "blue";
  }
}

const statusLabels: Record<string, string> = {
  RECEIVED: "Queued",
  VALIDATING: "Validating",
  FETCHING: "Fetching source",
  DETECTING: "Detecting",
  BUILDING: "Building",
  ARTIFACT_READY: "Artifact ready",
  STARTING_CANDIDATE: "Starting",
  HEALTH_CHECKING: "Health checks",
  READY: "Ready to promote",
  PROMOTION_INTENT: "Promoting",
  ROUTER_SWITCHED: "Promoting",
  COMMITTING_POINTER: "Promoting",
  DRAINING_OLD: "Draining previous",
  SUCCEEDED: "Ready",
  FAILED: "Failed",
  SUPERSEDED: "Superseded",
  CANCELLED: "Cancelled",
};

export function StatusBadge({ status }: { status: string }) {
  const tone = statusTone(status);
  const live = tone === "blue";
  return (
    <Badge tone={tone}>
      <span className={cx("h-1.5 w-1.5 rounded-full bg-current", live && "animate-pulse")} />
      {statusLabels[status] ?? status}
    </Badge>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 px-6 py-12 text-center">
      <p className="text-sm font-medium text-zinc-200">{title}</p>
      {children && <div className="mt-1 max-w-md text-sm text-zinc-500">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Alert({ tone = "red", title, children }: { tone?: "red" | "amber" | "blue" | "green"; title?: string; children?: ReactNode }) {
  const c = { red: "border-red-500/30 bg-red-500/10 text-red-200", amber: "border-amber-500/30 bg-amber-500/10 text-amber-100", blue: "border-sky-500/30 bg-sky-500/10 text-sky-100", green: "border-emerald-500/30 bg-emerald-500/10 text-emerald-100" }[tone];
  return (
    <div className={cx("rounded-md border px-3 py-2 text-sm", c)} role={tone === "red" ? "alert" : "status"}>
      {title && <p className="font-medium">{title}</p>}
      {children && <div className={title ? "mt-0.5 opacity-90" : ""}>{children}</div>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, footer, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    ref.current?.querySelector<HTMLElement>("input,textarea,select,button")?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-label={title} className={cx("w-full rounded-lg border border-zinc-800 bg-zinc-900 shadow-2xl", wide ? "max-w-2xl" : "max-w-md")}>
        <div className="border-b border-zinc-800 px-5 py-3">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
        </div>
        <div className="space-y-4 px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-zinc-800 px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      size="sm"
      variant="ghost"
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard unavailable */
        }
      }}
    >
      {done ? "Copied" : label}
    </Button>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-200">{children}</code>;
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div className="mb-5 flex gap-1 border-b border-zinc-800">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={cx("-mb-px border-b-2 px-3 py-2 text-sm", value === t.id ? "border-indigo-500 text-white" : "border-transparent text-zinc-400 hover:text-zinc-200")}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ---- toasts ------------------------------------------------------------------

type Toast = { id: number; tone: "green" | "red" | "blue"; text: string };
const ToastCtx = createContext<(tone: Toast["tone"], text: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const push = useCallback((tone: Toast["tone"], text: string) => {
    const id = Date.now() + Math.random();
    setItems((xs) => [...xs, { id, tone, text }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 5000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2">
        {items.map((t) => (
          <div
            key={t.id}
            className={cx(
              "pointer-events-auto rounded-md border px-3 py-2 text-sm shadow-lg",
              t.tone === "green" && "border-emerald-500/30 bg-emerald-950 text-emerald-100",
              t.tone === "red" && "border-red-500/30 bg-red-950 text-red-100",
              t.tone === "blue" && "border-sky-500/30 bg-sky-950 text-sky-100",
            )}
          >
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  return useContext(ToastCtx);
}
