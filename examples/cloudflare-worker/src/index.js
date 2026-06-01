function jsonError(status, code, message) {
  return Response.json(
    { ok: false, error: { code, message } },
    { status },
  );
}

async function readJsonWithLimit(request, maxBytes) {
  if (!request.body) {
    throw new Error("Missing request body");
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    bytesRead += value.byteLength;
    if (bytesRead > maxBytes) {
      await reader.cancel();
      throw new Error("Request body too large");
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  return JSON.parse(text);
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return jsonError(405, "METHOD_NOT_ALLOWED", "Only POST is allowed");
    }

    let payload;
    try {
      payload = await readJsonWithLimit(request, 1024 * 1024);
    } catch {
      return jsonError(400, "INVALID_REQUEST", "Request body must be valid JSON");
    }

    try {
      const endpoint = new URL("/proxy/fetch", env.PROXY_ENDPOINT);
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          authorization: `Bearer ${env.PROXY_TOKEN}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      return new Response(response.body, {
        status: response.status,
        headers: {
          "content-type": response.headers.get("content-type") || "application/json",
        },
      });
    } catch {
      return jsonError(502, "PROXY_UNAVAILABLE", "Proxy server is unavailable");
    }
  },
};
