import assert from "node:assert/strict";
import test from "node:test";

import {
  ProxyError,
  assertPublicIp,
  buildServer,
  loadConfig,
  proxyFetch,
} from "../src/server.js";

const TOKEN = "test-token-with-at-least-16-characters";
const PUBLIC_DNS = async () => [{ address: "8.8.8.8", family: 4 }];

function makeConfig(overrides = {}) {
  return {
    proxyToken: TOKEN,
    allowedHosts: new Set(["allowed.example", "other.example"]),
    host: "127.0.0.1",
    port: 8787,
    rateLimitMax: 100,
    rateLimitWindow: "1 minute",
    maxResponseBytes: 5 * 1024 * 1024,
    maxRedirects: 5,
    logLevel: "silent",
    ...overrides,
  };
}

function authorizedHeaders() {
  return { authorization: `Bearer ${TOKEN}` };
}

async function createApp(options = {}) {
  return buildServer({
    config: makeConfig(options.config),
    logger: false,
    resolveHostname: options.resolveHostname || PUBLIC_DNS,
    sendRequest:
      options.sendRequest ||
      (async () => ({
        statusCode: 200,
        headers: { "content-type": "text/plain" },
        bodyText: "ok",
      })),
  });
}

test("health endpoint is available without authentication", async (t) => {
  const app = await createApp();
  t.after(() => app.close());

  const response = await app.inject({ method: "GET", url: "/healthz" });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { ok: true });
});

test("proxy endpoint forwards an allowlisted HTTPS request", async (t) => {
  let captured;
  const app = await createApp({
    sendRequest: async (request) => {
      captured = request;
      return {
        statusCode: 200,
        headers: { "content-type": "application/json" },
        bodyText: '{"campus":true}',
      };
    },
  });
  t.after(() => app.close());

  const response = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: authorizedHeaders(),
    payload: {
      url: "https://allowed.example/resource?ticket=secret",
      method: "POST",
      headers: { Cookie: "session=secret" },
      body: { hello: "world" },
    },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), {
    ok: true,
    status: 200,
    headers: { "content-type": "application/json" },
    body: '{"campus":true}',
    contentType: "application/json",
  });
  assert.equal(captured.url.hostname, "allowed.example");
  assert.equal(captured.headers.cookie, "session=secret");
  assert.equal(captured.headers["accept-encoding"], "identity");
  assert.equal(captured.body, '{"hello":"world"}');
});

test("proxy endpoint requires a valid bearer token", async (t) => {
  const app = await createApp();
  t.after(() => app.close());

  const missing = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    payload: { url: "https://allowed.example" },
  });
  const wrong = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: { authorization: "Bearer incorrect-token-value" },
    payload: { url: "https://allowed.example" },
  });

  assert.equal(missing.statusCode, 401);
  assert.equal(missing.json().error.code, "UNAUTHORIZED");
  assert.equal(wrong.statusCode, 401);
  assert.equal(wrong.json().error.code, "UNAUTHORIZED");
});

test("rejects HTTP and non-allowlisted targets", async (t) => {
  const app = await createApp();
  t.after(() => app.close());

  const http = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: authorizedHeaders(),
    payload: { url: "http://allowed.example" },
  });
  const nonAllowlisted = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: authorizedHeaders(),
    payload: { url: "https://localhost" },
  });

  assert.equal(http.statusCode, 400);
  assert.equal(http.json().error.code, "URL_NOT_ALLOWED");
  assert.equal(nonAllowlisted.statusCode, 400);
  assert.equal(nonAllowlisted.json().error.code, "URL_NOT_ALLOWED");
});

test("rejects private, metadata, and IPv4-mapped DNS addresses", async () => {
  assert.throws(() => assertPublicIp("127.0.0.1"), {
    code: "DNS_BLOCKED",
  });
  assert.throws(() => assertPublicIp("169.254.169.254"), {
    code: "DNS_BLOCKED",
  });
  assert.throws(() => assertPublicIp("::ffff:192.168.1.1"), {
    code: "DNS_BLOCKED",
  });
});

test("rejects allowlisted hostname when DNS points to an internal address", async (t) => {
  const app = await createApp({
    resolveHostname: async () => [{ address: "192.168.2.1", family: 4 }],
  });
  t.after(() => app.close());

  const response = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: authorizedHeaders(),
    payload: { url: "https://allowed.example" },
  });

  assert.equal(response.statusCode, 400);
  assert.equal(response.json().error.code, "DNS_BLOCKED");
});

test("rejects timeout above 30 seconds", async (t) => {
  const app = await createApp();
  t.after(() => app.close());

  const response = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: authorizedHeaders(),
    payload: { url: "https://allowed.example", timeoutMs: 30_001 },
  });

  assert.equal(response.statusCode, 400);
  assert.equal(response.json().error.code, "INVALID_REQUEST");
});

test("rejects invalid configured port", () => {
  assert.throws(
    () =>
      loadConfig({
        PROXY_TOKEN: TOKEN,
        PORT: "65536",
      }),
    /PORT must be between 1 and 65535/,
  );
});

test("rejects incoming payload larger than 1 MiB", async (t) => {
  const app = await createApp();
  t.after(() => app.close());

  const response = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: {
      ...authorizedHeaders(),
      "content-type": "application/json",
    },
    payload: JSON.stringify({
      url: "https://allowed.example",
      method: "POST",
      body: "x".repeat(1024 * 1024),
    }),
  });

  assert.equal(response.statusCode, 413);
  assert.equal(response.json().error.code, "INVALID_REQUEST");
});

test("returns a uniform error for unsupported content type", async (t) => {
  const app = await createApp();
  t.after(() => app.close());

  const response = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: {
      ...authorizedHeaders(),
      "content-type": "application/xml",
    },
    payload: "<request />",
  });

  assert.equal(response.statusCode, 415);
  assert.deepEqual(response.json(), {
    ok: false,
    error: {
      code: "INVALID_REQUEST",
      message: "Invalid request",
    },
  });
});

test("rejects redirects to a non-allowlisted hostname", async () => {
  await assert.rejects(
    () =>
      proxyFetch(
        { url: "https://allowed.example/start" },
        makeConfig(),
        {
          resolveHostname: PUBLIC_DNS,
          sendRequest: async () => ({
            statusCode: 302,
            headers: { location: "https://blocked.example/next" },
            bodyText: "",
          }),
        },
      ),
    { code: "URL_NOT_ALLOWED" },
  );
});

test("strips credentials when redirecting between allowlisted origins", async () => {
  const requests = [];
  const result = await proxyFetch(
    {
      url: "https://allowed.example/start",
      headers: {
        Authorization: "Bearer upstream-secret",
        Cookie: "session=secret",
      },
    },
    makeConfig(),
    {
      resolveHostname: PUBLIC_DNS,
      sendRequest: async (request) => {
        requests.push(request);
        if (requests.length === 1) {
          return {
            statusCode: 302,
            headers: { location: "https://other.example/next" },
            bodyText: "",
          };
        }
        return {
          statusCode: 200,
          headers: { "content-type": "text/plain" },
          bodyText: "done",
        };
      },
    },
  );

  assert.equal(result.body, "done");
  assert.equal(requests.length, 2);
  assert.equal(requests[0].headers.authorization, "Bearer upstream-secret");
  assert.equal(requests[0].headers.cookie, "session=secret");
  assert.equal(requests[1].headers.authorization, undefined);
  assert.equal(requests[1].headers.cookie, undefined);
});

test("shares one timeout budget across redirects", async () => {
  const requests = [];
  await proxyFetch(
    {
      url: "https://allowed.example/start",
      timeoutMs: 1000,
    },
    makeConfig(),
    {
      resolveHostname: PUBLIC_DNS,
      sendRequest: async (request) => {
        requests.push(request);
        if (requests.length === 1) {
          await new Promise((resolve) => setTimeout(resolve, 20));
          return {
            statusCode: 302,
            headers: { location: "/next" },
            bodyText: "",
          };
        }
        return {
          statusCode: 200,
          headers: { "content-type": "text/plain" },
          bodyText: "done",
        };
      },
    },
  );

  assert.equal(requests.length, 2);
  assert.ok(requests[0].timeoutMs <= 1000);
  assert.ok(requests[1].timeoutMs < requests[0].timeoutMs);
});

test("applies the timeout budget to DNS resolution", async () => {
  await assert.rejects(
    () =>
      proxyFetch(
        {
          url: "https://allowed.example/start",
          timeoutMs: 20,
        },
        makeConfig(),
        {
          resolveHostname: async () => new Promise(() => {}),
        },
      ),
    { code: "UPSTREAM_TIMEOUT" },
  );
});

test("returns a uniform error for oversized upstream responses", async (t) => {
  const app = await createApp({
    sendRequest: async () => {
      throw new ProxyError(
        "UPSTREAM_RESPONSE_TOO_LARGE",
        "Upstream response exceeds configured limit",
        502,
      );
    },
  });
  t.after(() => app.close());

  const response = await app.inject({
    method: "POST",
    url: "/proxy/fetch",
    headers: authorizedHeaders(),
    payload: { url: "https://allowed.example" },
  });

  assert.equal(response.statusCode, 502);
  assert.equal(response.json().error.code, "UPSTREAM_RESPONSE_TOO_LARGE");
});

test("returns a uniform rate-limit error", async (t) => {
  const app = await createApp({ config: { rateLimitMax: 1 } });
  t.after(() => app.close());

  const first = await app.inject({ method: "GET", url: "/healthz" });
  const second = await app.inject({ method: "GET", url: "/healthz" });

  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 429);
  assert.equal(second.json().error.code, "RATE_LIMITED");
});
