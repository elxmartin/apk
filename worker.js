var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var ALLOWED_REPORT_FILES = /* @__PURE__ */ new Set(["secrets.txt.enc", "mobsfscan.json.enc", "cve.json.enc"]);
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = responseHeaders(request, env);
    if (request.method === "OPTIONS") return new Response(null, { headers });
    if (!isAllowedOrigin(request, env)) return textResponse("Forbidden", 403, headers);
    try {
      if (url.pathname === "/api/status" && request.method === "GET") {
        return await fetchProtectedAsset("/status.enc", env, headers);
      }
      if (url.pathname === "/api/report" && request.method === "GET") {
        return await handleReportRequest(url, env, headers);
      }
      return textResponse("Not found", 404, headers);
    } catch (error) {
      console.error("Workspace gateway error", error);
      return textResponse("Service unavailable", 503, headers);
    }
  }
};
__name(worker_default, "default");

async function handleReportRequest(url, env, headers) {
  const id = url.searchParams.get("id") || "";
  const file = url.searchParams.get("file") || "";
  if (!/^[a-f0-9]{64}$/.test(id) || !ALLOWED_REPORT_FILES.has(file)) {
    return textResponse("Not found", 404, headers);
  }
  return fetchProtectedAsset(`/reports/${id}/${file}`, env, headers);
}
__name(handleReportRequest, "handleReportRequest");

async function fetchProtectedAsset(path, env, headers) {
  const siteOrigin = (env.PUBLIC_SITE_ORIGIN || "https://elxmartin.github.io/apk").replace(/\/$/, "");
  const assetResponse = await fetch(`${siteOrigin}${path}`, { cf: { cacheTtl: 60, cacheEverything: true } });
  if (!assetResponse.ok) return textResponse("Not found", assetResponse.status, headers);
  return new Response(assetResponse.body, {
    status: 200,
    headers: { ...headers, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
  });
}
__name(fetchProtectedAsset, "fetchProtectedAsset");

function responseHeaders(request, env) {
  return {
    "Access-Control-Allow-Origin": env.DASHBOARD_ORIGIN || "https://elxmartin.github.io",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer"
  };
}
__name(responseHeaders, "responseHeaders");

function isAllowedOrigin(request, env) {
  const origin = request.headers.get("Origin");
  return !origin || origin === (env.DASHBOARD_ORIGIN || "https://elxmartin.github.io");
}
__name(isAllowedOrigin, "isAllowedOrigin");

function textResponse(body, status, headers) {
  return new Response(body, { status, headers: { ...headers, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
}
__name(textResponse, "textResponse");

export {
  worker_default as default
};