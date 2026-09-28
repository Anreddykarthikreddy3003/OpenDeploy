import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, setCsrf, setReauthHandler } from "../api/client";
import { parseDotenv } from "../components/EnvEditor";
import { StatusBadge } from "../components/ui";
import { shortSha } from "../lib/format";

describe("parseDotenv", () => {
  it("parses assignments, quotes, export and comments", () => {
    expect(parseDotenv('# c\nA=1\nexport B="two words"\nC=\'x=y\'\nbad line\n1X=no\n')).toEqual([
      { key: "A", value: "1" },
      { key: "B", value: "two words" },
      { key: "C", value: "x=y" },
    ]);
  });
});

describe("api client", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    setCsrf("");
    setReauthHandler(null);
  });

  it("sends the CSRF token only on mutating requests", async () => {
    const calls: RequestInit[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_u: string, init: RequestInit) => {
      calls.push(init);
      return new Response("{}", { status: 200 });
    }));
    setCsrf("tok123");
    await api("GET", "/api/v2/projects");
    await api("POST", "/api/v2/projects", { a: 1 });
    expect((calls[0].headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
    expect((calls[1].headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok123");
    expect(calls[1].credentials).toBe("same-origin");
  });

  it("retries once after a successful re-authentication", async () => {
    let n = 0;
    vi.stubGlobal("fetch", vi.fn(async () => {
      n++;
      return n === 1 ? new Response(JSON.stringify({ code: "reauth_required", message: "again" }), { status: 401 }) : new Response('{"ok":true}', { status: 200 });
    }));
    const handler = vi.fn(async () => true);
    setReauthHandler(handler);
    await expect(api("DELETE", "/api/v2/projects/x")).resolves.toEqual({ ok: true });
    expect(handler).toHaveBeenCalledOnce();
    expect(n).toBe(2);
  });

  it("surfaces structured API errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ code: "conflict", message: "exists" }), { status: 409 })));
    await expect(api("POST", "/x", {})).rejects.toMatchObject({ status: 409, code: "conflict", message: "exists" } as Partial<ApiError>);
  });
});

describe("presentation", () => {
  it("labels deployment states for humans", () => {
    render(<StatusBadge status="HEALTH_CHECKING" />);
    expect(screen.getByText("Health checks")).toBeInTheDocument();
  });
  it("hides upload pseudo-SHAs", () => {
    expect(shortSha("archive-dep_x")).toBe("");
    expect(shortSha("0123456789abcdef")).toBe("0123456");
  });
});
