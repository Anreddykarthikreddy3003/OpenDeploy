import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({ user: { role: "viewer", email: "v@example.com", name: "" } as any, logout: vi.fn() }));
vi.mock("../auth", () => ({ useAuth: () => auth }));

// This project runs vitest without globals, so testing-library does not clean up by itself.
afterEach(cleanup);

import { Layout, visibleNav } from "../components/Layout";
import { SessionLabel } from "../pages/Account";

function renderLayout(role: string) {
  auth.user = { role, email: `${role}@example.com`, name: "" };
  render(
    <MemoryRouter>
      <Layout />
    </MemoryRouter>,
  );
  // The narrow-screen header (the sidebar is hidden below the md breakpoint).
  return within(screen.getByRole("banner"));
}

describe("narrow-screen header", () => {
  it("offers Sign out", () => {
    const header = renderLayout("owner");
    header.getByRole("button", { name: "Sign out" }).click();
    expect(auth.logout).toHaveBeenCalled();
  });

  it("shows the same links as the sidebar for each role", () => {
    const header = renderLayout("viewer");
    expect(header.queryByRole("link", { name: "Platform" })).toBeNull();
    expect(header.getByRole("link", { name: "Account" })).toBeInTheDocument();
  });

  it("shows Platform to owners and admins", () => {
    expect(visibleNav("owner").map((n) => n.label)).toContain("Platform");
    expect(visibleNav("admin").map((n) => n.label)).toContain("Platform");
    expect(visibleNav("developer").map((n) => n.label)).not.toContain("Platform");
  });
});

describe("session label", () => {
  it("keeps the current-session badge outside the truncated user agent", () => {
    render(<SessionLabel agent={"Mozilla/5.0 ".repeat(20)} current />);
    const badge = screen.getByText("this session");
    expect(badge.closest(".truncate")).toBeNull();
  });
});
