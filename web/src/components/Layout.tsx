import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";
import { cx } from "./ui";

const nav = [
  { to: "/", label: "Projects", end: true },
  { to: "/new", label: "Import project" },
  { to: "/settings", label: "Platform", owner: true },
  { to: "/account", label: "Account" },
];

export function Layout() {
  const { user, logout } = useAuth();
  return (
    <div className="flex min-h-full">
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-zinc-800 bg-zinc-950 md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <span className="font-semibold text-white">OpenDeploy</span>
        </div>
        <nav className="flex-1 space-y-0.5 px-2">
          {nav
            .filter((n) => !n.owner || user?.role === "owner" || user?.role === "admin")
            .map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                className={({ isActive }) => cx("block rounded-md px-3 py-2 text-sm", isActive ? "bg-zinc-800 text-white" : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100")}
              >
                {n.label}
              </NavLink>
            ))}
        </nav>
        <div className="border-t border-zinc-800 p-3">
          <p className="truncate text-sm text-zinc-200">{user?.name || user?.email}</p>
          <p className="truncate text-xs text-zinc-500">
            {user?.email} · {user?.role}
          </p>
          <button onClick={logout} className="mt-2 text-xs text-zinc-400 hover:text-white">
            Sign out
          </button>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-zinc-800 px-4 py-3 md:hidden">
          <span className="font-semibold text-white">OpenDeploy</span>
          <div className="flex gap-3 text-sm">
            {nav.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => (isActive ? "text-white" : "text-zinc-400")}>
                {n.label}
              </NavLink>
            ))}
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 md:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
