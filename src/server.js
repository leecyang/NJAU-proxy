import "dotenv/config";

import { timingSafeEqual } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { fileURLToPath } from "node:url";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";

import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import ipaddr from "ipaddr.js";
import { Agent, request as undiciRequest } from "undici";

const DEFAULT_ALLOWED_HOSTS = [
  "libyy.njau.edu.cn",
  "authserver.njau.edu.cn",
  "vpn2.njau.edu.cn",
];
const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "DELETE"]);
const BLOCKED_REQUEST_HEADERS = new Set([
  "accept-encoding",
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 30_000;
const MAX_REQUEST_BODY_BYTES = 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 5;

export class ProxyError extends Error {
  constructor(code, message, statusCode = 400) {
    super(message);
    this.name = "ProxyError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

function parsePositiveInteger(value, fallback, name) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function parsePort(value) {
  const port = parsePositiveInteger(value, 8787, "PORT");
  if (port > 65_535) {
    throw new Error("PORT must be between 1 and 65535");
  }
  return port;
}

function parseAllowedHosts(value) {
  const hosts = (value ? value.split(",") : DEFAULT_ALLOWED_HOSTS)
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
  if (hosts.length === 0) {
    throw new Error("ALLOWED_HOSTS must contain at least one hostname");
  }
  return new Set(hosts);
}

export function loadConfig(env = process.env) {
  const proxyToken = env.PROXY_TOKEN;
  if (!proxyToken || proxyToken.length < 16) {
    throw new Error("PROXY_TOKEN must be set and contain at least 16 characters");
  }

  return {
    proxyToken,
    allowedHosts: parseAllowedHosts(env.ALLOWED_HOSTS),
    host: env.HOST || "127.0.0.1",
    port: parsePort(env.PORT),
    rateLimitMax: parsePositiveInteger(env.RATE_LIMIT_MAX, 60, "RATE_LIMIT_MAX"),
    rateLimitWindow: env.RATE_LIMIT_WINDOW || "1 minute",
    maxResponseBytes: parsePositiveInteger(
      env.MAX_RESPONSE_BYTES,
      DEFAULT_MAX_RESPONSE_BYTES,
      "MAX_RESPONSE_BYTES",
    ),
    maxRedirects: DEFAULT_MAX_REDIRECTS,
    logLevel: env.LOG_LEVEL || "info",
  };
}

function stripAddressBrackets(address) {
  return address.startsWith("[") && address.endsWith("]")
    ? address.slice(1, -1)
    : address;
}

export function assertPublicIp(address) {
  const normalized = stripAddressBrackets(address);
  if (!ipaddr.isValid(normalized)) {
    throw new ProxyError("DNS_BLOCKED", "Target resolved to an invalid IP address");
  }

  const parsed = ipaddr.parse(normalized);
  if (parsed.kind() === "ipv6" && parsed.isIPv4MappedAddress()) {
    throw new ProxyError("DNS_BLOCKED", "IPv4-mapped IPv6 addresses are not allowed");
  }
  if (parsed.range() !== "unicast") {
    throw new ProxyError("DNS_BLOCKED", "Target resolved to a non-public IP address");
  }
  return normalized;
}

export async function resolvePublicAddresses(hostname, resolveHostname = dnsLookup) {
  let records;
  try {
    records = await resolveHostname(hostname, { all: true, verbatim: true });
  } catch {
    throw new ProxyError("DNS_LOOKUP_FAILED", "Unable to resolve target hostname", 502);
  }

  if (!Array.isArray(records) || records.length === 0) {
    throw new ProxyError("DNS_LOOKUP_FAILED", "Target hostname has no addresses", 502);
  }

  const addresses = records.map((record) => {
    const address = typeof record === "string" ? record : record.address;
    const normalized = assertPublicIp(address);
    return {
      address: normalized,
      family: ipaddr.parse(normalized).kind() === "ipv6" ? 6 : 4,
    };
  });

  return addresses;
}

export async function validateTargetUrl(rawUrl, config, resolveHostname = dnsLookup) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ProxyError("INVALID_REQUEST", "url must be a valid absolute URL");
  }

  if (url.protocol !== "https:") {
    throw new ProxyError("URL_NOT_ALLOWED", "Only HTTPS URLs are allowed");
  }
  if (url.port && url.port !== "443") {
    throw new ProxyError("URL_NOT_ALLOWED", "Only HTTPS port 443 is allowed");
  }
  if (url.username || url.password) {
    throw new ProxyError("URL_NOT_ALLOWED", "URLs containing credentials are not allowed");
  }
  if (!config.allowedHosts.has(url.hostname.toLowerCase())) {
    throw new ProxyError("URL_NOT_ALLOWED", "Target hostname is not allowlisted");
  }

  const addresses = await resolvePublicAddresses(url.hostname, resolveHostname);
  return { url, addresses };
}

function tokensMatch(actual, expected) {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  return (
    actualBuffer.length === expectedBuffer.length &&
    timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

function assertAuthorized(header, expectedToken) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    throw new ProxyError("UNAUTHORIZED", "Missing or invalid bearer token", 401);
  }
  if (!tokensMatch(header.slice("Bearer ".length), expectedToken)) {
    throw new ProxyError("UNAUTHORIZED", "Missing or invalid bearer token", 401);
  }
}

function normalizeRequestHeaders(input) {
  if (input === undefined) {
    return {};
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new ProxyError("INVALID_REQUEST", "headers must be an object");
  }

  const headers = {};
  for (const [rawName, rawValue] of Object.entries(input)) {
    const name = rawName.toLowerCase();
    if (BLOCKED_REQUEST_HEADERS.has(name)) {
      continue;
    }
    if (typeof rawValue !== "string") {
      throw new ProxyError("INVALID_REQUEST", `Header ${rawName} must be a string`);
    }
    headers[name] = rawValue;
  }
  headers["accept-encoding"] = "identity";
  return headers;
}

function normalizeBody(body, method, headers) {
  if (body === undefined || body === null) {
    return undefined;
  }
  if (method === "GET") {
    throw new ProxyError("INVALID_REQUEST", "GET requests cannot include a body");
  }

  let normalized;
  if (typeof body === "string") {
    normalized = body;
  } else {
    try {
      normalized = JSON.stringify(body);
    } catch {
      throw new ProxyError("INVALID_REQUEST", "body must be JSON serializable");
    }
    if (!headers["content-type"]) {
      headers["content-type"] = "application/json";
    }
  }

  if (Buffer.byteLength(normalized) > MAX_REQUEST_BODY_BYTES) {
    throw new ProxyError("INVALID_REQUEST", "Forwarded body exceeds 1 MiB limit", 413);
  }
  return normalized;
}

function parseFetchRequest(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ProxyError("INVALID_REQUEST", "Request body must be a JSON object");
  }
  if (typeof payload.url !== "string" || payload.url.length === 0) {
    throw new ProxyError("INVALID_REQUEST", "url is required");
  }

  const method = (payload.method || "GET").toUpperCase();
  if (!ALLOWED_METHODS.has(method)) {
    throw new ProxyError("INVALID_REQUEST", "method must be GET, POST, PUT, or DELETE");
  }

  const timeoutMs = payload.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new ProxyError("INVALID_REQUEST", "timeoutMs must be an integer from 1 to 30000");
  }

  const headers = normalizeRequestHeaders(payload.headers);
  const body = normalizeBody(payload.body, method, headers);
  return { url: payload.url, method, headers, body, timeoutMs };
}

function createPinnedLookup(addresses) {
  return (_hostname, options, callback) => {
    const requestedFamily = Number(options?.family || 0);
    const matches = requestedFamily
      ? addresses.filter((entry) => entry.family === requestedFamily)
      : addresses;
    const selected = matches.length > 0 ? matches : addresses;

    if (options?.all) {
      callback(null, selected);
      return;
    }
    callback(null, selected[0].address, selected[0].family);
  };
}

function decodedStream(body, contentEncoding) {
  const encoding = String(contentEncoding || "identity").toLowerCase().trim();
  if (!encoding || encoding === "identity") {
    return body;
  }
  if (encoding === "gzip") {
    return body.pipe(createGunzip());
  }
  if (encoding === "deflate") {
    return body.pipe(createInflate());
  }
  if (encoding === "br") {
    return body.pipe(createBrotliDecompress());
  }
  throw new ProxyError("UPSTREAM_ENCODING_NOT_SUPPORTED", "Unsupported upstream encoding", 502);
}

async function readLimitedText(stream, maxBytes) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > maxBytes) {
      stream.destroy();
      throw new ProxyError(
        "UPSTREAM_RESPONSE_TOO_LARGE",
        "Upstream response exceeds configured limit",
        502,
      );
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function normalizeResponseHeaders(input) {
  const headers = {};
  for (const [name, value] of Object.entries(input || {})) {
    const lowerName = name.toLowerCase();
    if (lowerName === "content-encoding" || lowerName === "content-length") {
      continue;
    }
    headers[lowerName] = value;
  }
  return headers;
}

export async function sendPinnedRequest({
  url,
  method,
  headers,
  body,
  timeoutMs,
  addresses,
  maxResponseBytes,
}) {
  const dispatcher = new Agent({
    connect: {
      lookup: createPinnedLookup(addresses),
    },
  });

  try {
    const response = await undiciRequest(url, {
      dispatcher,
      method,
      headers,
      body,
      signal: AbortSignal.timeout(timeoutMs),
      maxRedirections: 0,
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
    });
    const stream = decodedStream(response.body, response.headers["content-encoding"]);
    return {
      statusCode: response.statusCode,
      headers: normalizeResponseHeaders(response.headers),
      bodyText: await readLimitedText(stream, maxResponseBytes),
    };
  } catch (error) {
    if (error instanceof ProxyError) {
      throw error;
    }
    if (
      error?.name === "AbortError" ||
      error?.name === "TimeoutError" ||
      error?.code === "UND_ERR_HEADERS_TIMEOUT" ||
      error?.code === "UND_ERR_BODY_TIMEOUT" ||
      error?.code === "UND_ERR_CONNECT_TIMEOUT"
    ) {
      throw new ProxyError("UPSTREAM_TIMEOUT", "Upstream request timed out", 504);
    }
    throw new ProxyError("UPSTREAM_ERROR", "Upstream request failed", 502);
  } finally {
    await dispatcher.close();
  }
}

function isRedirect(response) {
  return REDIRECT_STATUSES.has(response.statusCode) && response.headers.location;
}

function redirectedRequest(previous, statusCode, nextUrl) {
  const headers = { ...previous.headers };
  let method = previous.method;
  let body = previous.body;

  if (statusCode === 303 || ((statusCode === 301 || statusCode === 302) && method === "POST")) {
    method = "GET";
    body = undefined;
    delete headers["content-type"];
  }

  const previousOrigin = new URL(previous.url).origin;
  if (nextUrl.origin !== previousOrigin) {
    delete headers.authorization;
    delete headers.cookie;
  }

  return { ...previous, url: nextUrl.href, method, body, headers };
}

export async function proxyFetch(
  input,
  config,
  {
    resolveHostname = dnsLookup,
    sendRequest = sendPinnedRequest,
  } = {},
) {
  let request = parseFetchRequest(input);
  const deadline = Date.now() + request.timeoutMs;

  for (let redirectCount = 0; ; redirectCount += 1) {
    const remainingTimeoutMs = deadline - Date.now();
    if (remainingTimeoutMs <= 0) {
      throw new ProxyError("UPSTREAM_TIMEOUT", "Upstream request timed out", 504);
    }
    const { url, addresses } = await validateTargetUrl(
      request.url,
      config,
      resolveHostname,
    );
    const response = await sendRequest({
      ...request,
      url,
      addresses,
      timeoutMs: remainingTimeoutMs,
      maxResponseBytes: config.maxResponseBytes,
    });

    if (!isRedirect(response)) {
      return {
        ok: true,
        status: response.statusCode,
        headers: response.headers,
        body: response.bodyText,
        contentType: response.headers["content-type"] || "",
      };
    }
    if (redirectCount >= config.maxRedirects) {
      throw new ProxyError("TOO_MANY_REDIRECTS", "Upstream redirected too many times", 502);
    }

    let nextUrl;
    try {
      nextUrl = new URL(response.headers.location, url);
    } catch {
      throw new ProxyError("UPSTREAM_ERROR", "Upstream returned an invalid redirect URL", 502);
    }
    request = redirectedRequest(request, response.statusCode, nextUrl);
  }
}

function errorPayload(code, message) {
  return { ok: false, error: { code, message } };
}

export async function buildServer({
  config = loadConfig(),
  logger,
  resolveHostname = dnsLookup,
  sendRequest = sendPinnedRequest,
} = {}) {
  const app = Fastify({
    bodyLimit: MAX_REQUEST_BODY_BYTES,
    logger:
      logger ??
      {
        level: config.logLevel,
        redact: {
          paths: [
            "req.headers.authorization",
            "req.headers.cookie",
            "request.headers.authorization",
            "request.headers.cookie",
          ],
          censor: "[REDACTED]",
        },
      },
  });

  await app.register(rateLimit, {
    global: true,
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindow,
  });

  app.addHook("onRequest", async (request) => {
    if (request.url.startsWith("/proxy/")) {
      assertAuthorized(request.headers.authorization, config.proxyToken);
    }
  });

  app.get("/healthz", async () => ({ ok: true }));

  app.post("/proxy/fetch", async (request) => {
    const startedAt = Date.now();
    try {
      const result = await proxyFetch(request.body, config, {
        resolveHostname,
        sendRequest,
      });
      request.log.info(
        {
          targetHost: new URL(request.body.url).hostname,
          upstreamStatus: result.status,
          durationMs: Date.now() - startedAt,
        },
        "proxy request completed",
      );
      return result;
    } catch (error) {
      request.log.warn(
        {
          errorCode: error instanceof ProxyError ? error.code : "INTERNAL_ERROR",
          durationMs: Date.now() - startedAt,
        },
        "proxy request failed",
      );
      throw error;
    }
  });

  app.setNotFoundHandler((_request, reply) => {
    reply.code(404).send(errorPayload("NOT_FOUND", "Route not found"));
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof ProxyError) {
      reply.code(error.statusCode).send(errorPayload(error.code, error.message));
      return;
    }
    if (error.statusCode === 429) {
      reply.code(429).send(errorPayload("RATE_LIMITED", "Too many requests; please retry later"));
      return;
    }
    if (error.code === "FST_ERR_CTP_BODY_TOO_LARGE") {
      reply.code(413).send(errorPayload("INVALID_REQUEST", "Invalid request"));
      return;
    }
    if (Number.isInteger(error.statusCode) && error.statusCode >= 400 && error.statusCode < 500) {
      reply.code(error.statusCode || 400).send(errorPayload("INVALID_REQUEST", "Invalid request"));
      return;
    }
    _request.log.error({ err: error }, "unexpected proxy error");
    reply.code(500).send(errorPayload("INTERNAL_ERROR", "Internal server error"));
  });

  return app;
}

async function start() {
  const config = loadConfig();
  const app = await buildServer({ config });
  try {
    await app.listen({ host: config.host, port: config.port });
  } catch (error) {
    app.log.error(error);
    process.exitCode = 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await start();
}
