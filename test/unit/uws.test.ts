 
import { describe, it, expect } from "vitest";
import {
  createAuth,
  uwsAdapter,
  snapshotUwsRequest,
  createAdapters,
} from "../../src/index.js";
import type { UwsHttpRequest, UwsHttpResponse, UwsRequestSnapshot } from "../../src/index.js";

const SECRET = "uws-adapter-secret-key-for-tests-32";

interface MockRes extends UwsHttpResponse {
  status: string | null;
  headers: Record<string, string>;
  body: string | null;
  aborted: boolean;
  abortHandler: (() => void) | null;
}

function createMockRes(): MockRes {
  const result: MockRes = {
    status: null,
    headers: {},
    body: null,
    aborted: false,
    abortHandler: null,
    cork(cb: () => void) {
      cb();
    },
    writeStatus(status: string) {
      this.status = status;
    },
    writeHeader(key: string, value: string) {
      this.headers[key] = value;
    },
    end(body?: string | ArrayBuffer | Uint8Array) {
      this.body = body === undefined ? null : String(body);
    },
    onAborted(cb: () => void) {
      this.abortHandler = cb;
    },
  };
  return result;
}

function createMockReq({
  headers = {},
  method = "get",
  url = "/me",
  query = "",
}: {
  headers?: Record<string, string>;
  method?: string;
  url?: string;
  query?: string;
}): UwsHttpRequest {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = value;
  }
  return {
    getMethod: () => method,
    getUrl: () => url,
    getQuery: () => query,
    getHeader: (name: string) => normalized[name.toLowerCase()] ?? "",
    forEach(cb: (key: string, value: string) => void) {
      for (const [key, value] of Object.entries(normalized)) {
        cb(key, value);
      }
    },
  };
}

describe("uWebSockets.js adapter", () => {
  it("is exposed on createAdapters", () => {
    const auth = createAuth({ secret: SECRET });
    const adapters = createAdapters(auth);
    expect(typeof adapters.uws.authenticate).toBe("function");
    expect(typeof adapters.uWebSockets.authenticate).toBe("function");
    expect(typeof uwsAdapter).toBe("function");
  });

  it("snapshots headers before async work", () => {
    const res = createMockRes();
    const req = createMockReq({
      headers: { authorization: "Bearer token", cookie: "a=1" },
      query: "access_token=abc",
    });
    const snapshot = snapshotUwsRequest(res, req);
    expect(snapshot.headers.authorization).toBe("Bearer token");
    expect(snapshot.headers.cookie).toBe("a=1");
    expect(snapshot.query).toBe("access_token=abc");
    expect(snapshot.method).toBe("get");
  });

  it("authenticates a uWS request from Authorization header", async () => {
    const auth = createAuth({ secret: SECRET });
    const { accessToken } = await auth.login({ id: 21, roles: ["user"] });
    const { authenticate, json } = uwsAdapter(auth);
    const res = createMockRes();
    const req = createMockReq({ headers: { authorization: `Bearer ${accessToken}` } });

    await authenticate()((response, _request, snapshot?: UwsRequestSnapshot) => {
      json(response, 200, { userId: snapshot?.user?.userId });
    })(res, req);

    expect(res.status).toBe("200");
    expect(res.headers["Content-Type"]).toMatch(/application\/json/);
    expect(JSON.parse(res.body ?? "null").userId).toBe(21);
  });

  it("ignores the query string unless it is opted into", async () => {
    const auth = createAuth({ secret: SECRET });
    const { accessToken } = await auth.login({ id: 22, roles: ["user"] });
    const { authenticate } = uwsAdapter(auth);
    let rejected: unknown = null;

    await authenticate()((_res, _req, _snapshot?: UwsRequestSnapshot) => {
      rejected = new Error("should not have authenticated");
    })(createMockRes(), createMockReq({ query: `access_token=${accessToken}` }));

    expect(rejected).toBeNull();
  });

  it("authenticates from query string when opted in", async () => {
    const auth = createAuth({ secret: SECRET });
    const { accessToken } = await auth.login({ id: 22, roles: ["user"] });
    const { authenticate } = uwsAdapter(auth);
    const res = createMockRes();
    const req = createMockReq({ query: `access_token=${accessToken}` });
    let userId: string | number | null = null;

    await authenticate({ query: true })((_res, _req, snapshot?: UwsRequestSnapshot) => {
      userId = snapshot?.user?.userId ?? null;
    })(res, req);

    expect(userId).toBe(22);
  });

  it("rejects missing tokens", async () => {
    const auth = createAuth({ secret: SECRET });
    const { authenticate } = uwsAdapter(auth);
    const res = createMockRes();
    const req = createMockReq({});

    await authenticate()(() => {
      throw new Error("should not run");
    })(res, req);

    expect(res.status).toBe("401");
    expect(JSON.parse(res.body ?? "null").error).toBe("UNAUTHORIZED");
  });

  it("enforces permissions after authenticate", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: { roles: { user: { permissions: ["me.read"] } } },
    });
    const { accessToken } = await auth.login({ id: 7, roles: ["user"] });
    const { authenticate, requirePermission } = uwsAdapter(auth);
    const res = createMockRes();
    const req = createMockReq({ headers: { authorization: `Bearer ${accessToken}` } });

    await authenticate()(requirePermission("stats.read")(() => {
      throw new Error("should not run");
    }))(res, req);

    expect(res.status).toBe("403");
    expect(JSON.parse(res.body ?? "null").error).toBe("FORBIDDEN");
  });

  it("allows a granted permission", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: { roles: { user: { permissions: ["me.read"] } } },
    });
    const { accessToken } = await auth.login({ id: 8, roles: ["user"] });
    const { authenticate, requirePermission, json } = uwsAdapter(auth);
    const res = createMockRes();
    const req = createMockReq({ headers: { authorization: `Bearer ${accessToken}` } });

    await authenticate()(requirePermission("me.read")((response, _request, snapshot?: UwsRequestSnapshot) => {
      json(response, 200, { ok: true, userId: snapshot?.user?.userId });
    }))(res, req);

    expect(JSON.parse(res.body ?? "null").ok).toBe(true);
    expect(JSON.parse(res.body ?? "null").userId).toBe(8);
  });

  it("does not write after abort", async () => {
    const auth = createAuth({ secret: SECRET });
    const { accessToken } = await auth.login({ id: 9, roles: ["user"] });
    const { authenticate } = uwsAdapter(auth);
    const res = createMockRes();
    const req = createMockReq({ headers: { authorization: `Bearer ${accessToken}` } });

    const pending = authenticate()(() => {
      throw new Error("handler should not run");
    })(res, req);
    res.abortHandler?.();
    await pending;
    expect(res.body).toBeNull();
  });
});
