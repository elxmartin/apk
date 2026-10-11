var ALLOWED_REPORT_FILES = /* @__PURE__ */ new Set([
  "secrets.txt.enc", "mobsfscan.json.enc", "cve.json.enc",
  "secrets.txt", "mobsfscan.json", "cve.json"
]);

var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = responseHeaders(request, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    if (!isAllowedOrigin(request, env)) {
      return textResponse("Forbidden", 403, headers);
    }

    try {
      const isGetOrHead = request.method === "GET" || request.method === "HEAD";

      if (url.pathname === "/api/status" && isGetOrHead) {
        return await handleStatusRequest(env, headers);
      }
      if (url.pathname === "/api/report" && isGetOrHead) {
        return await handleReportRequest(url, env, headers);
      }
      // Graceful fallback for legacy cached clients still posting to login
      if (url.pathname === "/api/login") {
        return new Response(JSON.stringify({ status: "authenticated", message: "Authentication disabled" }), {
          status: 200,
          headers: { ...headers, "Content-Type": "application/json; charset=utf-8" }
        });
      }

      return textResponse("Not found", 404, headers);
    } catch (error) {
      console.error("Workspace gateway error", error);
      return textResponse("Service unavailable", 503, headers);
    }
  }
};

async function handleStatusRequest(env, headers) {
  const siteOrigin = (env.PUBLIC_SITE_ORIGIN || "https://elxmartin.github.io/apk").replace(/\/$/, "");

  // 1. Try serving unencrypted status.json if available
  try {
    const jsonResponse = await fetch(`${siteOrigin}/status.json?v=${Date.now()}`, { cf: { cacheTtl: 30, cacheEverything: true } });
    if (jsonResponse.ok) {
      const text = await jsonResponse.text();
      return new Response(text, {
        status: 200,
        headers: { ...headers, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
      });
    }
  } catch (err) {
    console.warn("Could not fetch unencrypted status.json:", err);
  }

  // 2. Fallback to status.enc (and decrypt with REPORT_ENCRYPTION_KEY if present)
  return await fetchProtectedAsset("/status.enc", env, headers);
}

async function handleReportRequest(url, env, headers) {
  const id = url.searchParams.get("id") || "";
  const file = url.searchParams.get("file") || "";
  if (!/^[a-f0-9]{64}$/.test(id) || !ALLOWED_REPORT_FILES.has(file)) {
    return textResponse("Not found", 404, headers);
  }

  const siteOrigin = (env.PUBLIC_SITE_ORIGIN || "https://elxmartin.github.io/apk").replace(/\/$/, "");
  const unencryptedFile = file.replace(/\.enc$/, "");

  // If unencrypted version exists on GitHub Pages, serve it directly
  if (file.endsWith(".enc")) {
    try {
      const plainRes = await fetch(`${siteOrigin}/reports/${id}/${unencryptedFile}?v=${Date.now()}`, { cf: { cacheTtl: 60, cacheEverything: true } });
      if (plainRes.ok) {
        const isJson = unencryptedFile.endsWith(".json");
        return new Response(plainRes.body, {
          status: 200,
          headers: {
            ...headers,
            "Content-Type": isJson ? "application/json; charset=utf-8" : "text/plain; charset=utf-8",
            "Cache-Control": "no-store"
          }
        });
      }
    } catch (e) {
      // Fall through to protected asset fetch
    }
  }

  return fetchProtectedAsset(`/reports/${id}/${file}`, env, headers);
}

async function fetchProtectedAsset(path, env, headers) {
  const siteOrigin = (env.PUBLIC_SITE_ORIGIN || "https://elxmartin.github.io/apk").replace(/\/$/, "");
  const assetResponse = await fetch(`${siteOrigin}${path}`, { cf: { cacheTtl: 60, cacheEverything: true } });
  if (!assetResponse.ok) return textResponse("Not found", assetResponse.status, headers);

  const rawText = await assetResponse.text();
  const encryptionKey = env.REPORT_ENCRYPTION_KEY;

  if (encryptionKey) {
    try {
      const decrypted = await decryptRawPayload(rawText, encryptionKey);
      const isJson = path.endsWith(".json.enc") || path.endsWith("/status.enc") || decrypted.trim().startsWith("{") || decrypted.trim().startsWith("[");
      return new Response(decrypted, {
        status: 200,
        headers: {
          ...headers,
          "Content-Type": isJson ? "application/json; charset=utf-8" : "text/plain; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });
    } catch (decErr) {
      console.error("Worker decryption error:", decErr);
    }
  }

  return new Response(rawText, {
    status: 200,
    headers: { ...headers, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
  });
}

async function decryptRawPayload(base64Str, passphrase) {
  const cleanBase64 = base64Str.replace(/\s+/g, '');
  let rawBinary;
  try {
    rawBinary = Uint8Array.from(atob(cleanBase64), c => c.charCodeAt(0));
  } catch (e) {
    throw new Error("Failed to decode Base64 payload.");
  }

  if (rawBinary.length < 16) {
    throw new Error("Payload size too short for valid OpenSSL container.");
  }

  const magic = new TextDecoder().decode(rawBinary.subarray(0, 8));
  if (magic !== "Salted__") {
    return base64Str;
  }

  const salt = rawBinary.subarray(8, 16);
  const ciphertext = rawBinary.subarray(16);

  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    passKey,
    384
  );

  const keyBytes = derivedBits.slice(0, 32);
  const ivBytes = derivedBits.slice(32, 48);

  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["decrypt"]
  );

  const decryptedGzipBuffer = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: ivBytes },
    aesKey,
    ciphertext
  );

  // Decompress Gzip Stream if compressed
  try {
    const stream = new Response(decryptedGzipBuffer).body.pipeThrough(new DecompressionStream('gzip'));
    return await new Response(stream).text();
  } catch {
    return new TextDecoder().decode(decryptedGzipBuffer);
  }
}

function normalizeOrigin(val) {
  if (!val) return "";
  try {
    return new URL(val).origin;
  } catch {
    return val.trim();
  }
}

function responseHeaders(request, env) {
  const requestOrigin = request.headers.get("Origin");
  let allowOrigin = "*";

  if (env.DASHBOARD_ORIGIN && env.DASHBOARD_ORIGIN !== "*") {
    const configuredOrigins = env.DASHBOARD_ORIGIN.split(",").map(o => normalizeOrigin(o)).filter(Boolean);
    if (requestOrigin && configuredOrigins.includes(requestOrigin)) {
      allowOrigin = requestOrigin;
    } else if (configuredOrigins.includes("*")) {
      allowOrigin = requestOrigin || "*";
    } else if (requestOrigin) {
      allowOrigin = requestOrigin;
    } else if (configuredOrigins.length > 0) {
      allowOrigin = configuredOrigins[0];
    }
  } else if (requestOrigin) {
    allowOrigin = requestOrigin;
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer"
  };
}

function isAllowedOrigin(request, env) {
  return true;
}

function textResponse(body, status, headers) {
  return new Response(body, {
    status,
    headers: { ...headers, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
  });
}

export {
  worker_default as default
};