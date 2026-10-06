// The fake API's route table, shared by the Vitest fake (fake-api.ts) and the Playwright layout check
// (e2e/), so it must not import Vitest.

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

/** The reply for one request, or null when no route matches. */
export async function resolve(
  routes: Routes,
  request: Omit<FakeRequest, "params">,
): Promise<{ request: FakeRequest; status: number; body: unknown } | null> {
  for (const [key, handler] of Object.entries(routes)) {
    const [routeMethod = "", pattern = ""] = key.split(" ");
    const params = routeMethod === request.method ? match(pattern, request.path) : null;
    if (!params) continue;
    const full = { ...request, params };
    const result = await (typeof handler === "function" ? (handler as (r: FakeRequest) => unknown)(full) : handler);
    const { status, body } = isReply(result) ? result : { status: 200, body: result };
    return { request: full, status, body };
  }
  return null;
}
