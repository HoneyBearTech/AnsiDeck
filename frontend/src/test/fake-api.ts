import { vi } from "vitest";

export interface FakeRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  params: Record<string, string>;
  body: unknown;
}

/** A canned reply: a plain value is JSON with status 200; `reply()` sets the status. */
export interface Reply {
  status: number;
  body: unknown;
}

export function reply(status: number, body: unknown = null): Reply {
  return { status, body };
}

export type Handler = unknown | ((request: FakeRequest) => unknown);
export type Routes = Record<string, Handler>;

function isReply(value: unknown): value is Reply {
  return typeof value === "object" && value !== null && "status" in value && "body" in value && Object.keys(value).length === 2;
}

function match(pattern: string, path: string): Record<string, string> | null {
  const want = pattern.split("/");
  const got = path.split("/");
  if (want.length !== got.length) return null;
  const params: Record<string, string> = {};
  for (const [i, part] of want.entries()) {
    const actual = got[i] ?? "";
    if (part.startsWith(":")) params[part.slice(1)] = actual;
    else if (part !== actual) return null;
  }
  return params;
}

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
    for (const [key, handler] of Object.entries(table)) {
      const [routeMethod = "", pattern = ""] = key.split(" ");
      const params = routeMethod === method ? match(pattern, path) : null;
      if (!params) continue;
      const request = { method, path, query: url.searchParams, params, body };
      calls.push(request);
      let result = typeof handler === "function" ? (handler as (r: FakeRequest) => unknown)(request) : handler;
      result = await result;
      const { status, body: payload } = isReply(result) ? result : { status: 200, body: result };
      return new Response(status === 204 ? null : JSON.stringify(payload), {
        status,
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
