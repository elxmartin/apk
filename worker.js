var ALLOWED_REPORT_FILES = /* @__PURE__ */ new Set(["secrets.txt.enc", "mobsfscan.json.enc", "cve.json.enc"]);

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
        return await fetchProtectedAsset("/status.enc", env, headers);
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

async function handleReportRequest(url, env, headers) {
  const id = url.searchParams.get("id") || "";
  const file = url.searchParams.get("file") || "";
  if (!/^[a-f0-9]{64}$/.test(id) || !ALLOWED_REPORT_FILES.has(file)) {
    return textResponse("Not found", 404, headers);
  }
  return fetchProtectedAsset(`/reports/${id}/${file}`, env, headers);
}

async function fetchProtectedAsset(path, env, headers) {
  const siteOrigin = (env.PUBLIC_SITE_ORIGIN || "https://elxmartin.github.io/apk").replace(/\/$/, "");
  const assetResponse = await fetch(`${siteOrigin}${path}`, { cf: { cacheTtl: 60, cacheEverything: true } });
  if (!assetResponse.ok) return textResponse("Not found", assetResponse.status, headers);
  return new Response(assetResponse.body, {
    status: 200,
    headers: { ...headers, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
  });
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

  // If DASHBOARD_ORIGIN is specified and not wildcard
  if (env.DASHBOARD_ORIGIN && env.DASHBOARD_ORIGIN !== "*") {
    const configuredOrigins = env.DASHBOARD_ORIGIN.split(",").map(o => normalizeOrigin(o)).filter(Boolean);
    if (requestOrigin && configuredOrigins.includes(requestOrigin)) {
      allowOrigin = requestOrigin;
    } else if (configuredOrigins.includes("*")) {
      allowOrigin = requestOrigin || "*";
    } else if (requestOrigin) {
      // Allow any requesting origin when auth is disabled so project can be merged anywhere
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
  // Authentication is disabled; allow all origins so project can be merged into any site/origin
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