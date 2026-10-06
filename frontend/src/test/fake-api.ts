import { vi } from "vitest";

import { type FakeRequest, resolve, type Routes } from "./api-routes";

export { type FakeRequest, type Handler, type Reply, reply, type Routes } from "./api-routes";

/**
 * Stubs fetch with an in-memory API. Routes are "METHOD /path/:param" (paths without the /api
 * prefix and query string). Every request is recorded; an unhandled one fails the test.
 */
export function fakeApi(routes: Routes) {
  const calls: FakeRequest[] = [];
  const unhandled: string[] = [];
  const table = { ...routes };

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const method = (init?.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(/^\/api/, "");
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    const resolved = await resolve(table, { method, path, query: url.searchParams, body });
    if (resolved) {
      calls.push(resolved.request);
      return new Response(resolved.status === 204 ? null : JSON.stringify(resolved.body), {
        status: resolved.status,
        headers: { "Content-Type": "application/json" },
      });
    }
    unhandled.push(`${method} ${path}`);
    return new Response(JSON.stringify({ detail: `unhandled ${method} ${path}` }), { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);

  return {
    calls,
    unhandled,
    /** Adds or replaces routes mid-test (e.g. what a list returns after a create). */
    set(more: Routes) {
      Object.assign(table, more);
    },
    /** The requests made to one route ("METHOD /path" with the real path). */
    requests(key: string): FakeRequest[] {
      const [method, path] = key.split(" ");
      return calls.filter((c) => c.method === method && c.path === path);
    },
  };
}

export type FakeApi = ReturnType<typeof fakeApi>;
