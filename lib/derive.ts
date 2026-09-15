import { createHash } from "crypto";
import { KNOWN_CIMD_CLIENTS, type Config } from "../config";

/**
 * Anything below 0x21 (including space, tab, newline and NUL) or DEL. Never legitimate unencoded in a URL, and
 * a classic way to make two parsers disagree about where a component ends.
 */
const CONTROL_OR_SPACE = /[\x00-\x20\x7f]/;
/** A '%' that does not begin a complete two-hex-digit escape. */
const MALFORMED_PERCENT = /%(?![0-9A-Fa-f]{2})/;
const AUTHORITY = /^[A-Za-z][A-Za-z0-9+.\-]*:\/\/[^/?#]*/;
const RAW_AUTHORITY = /^[A-Za-z][A-Za-z0-9+.\-]*:\/\/([^/?#]*)/;
const MAX_DECODES = 4;

/**
 * The authority must already be ASCII: letters, digits, hyphen, dot, plus colon and brackets for a port or an
 * IPv6 literal. Checked against the RAW text, not `url.hostname`, because that is where the two implementations
 * diverge: WHATWG percent-decodes the host and applies UTS-46 mapping, so `x.local%68ost` and the fullwidth
 * `ｅｘａｍｐｌｅ.com` arrive here as `x.localhost` and `example.com` while Python's `urlsplit` keeps them
 * verbatim. Left unchecked, synth would validate one host and the registrar would fetch another. Punycode
 * (`xn--...`) is LDH and still accepted. Mirrors HOST_SYNTAX in lambdas/shared/cimd_url.py.
 */
const HOST_SYNTAX = /^[A-Za-z0-9.:[\]-]+$/;

/** The path text exactly as written, before WHATWG parsing normalises dot segments away. Mirrors raw_path(). */
function rawPath(value: string): string {
  return value.replace(AUTHORITY, "").split(/[?#]/)[0];
}

/**
 * Reject dot segments and encoded separators under any amount of percent-decoding. Mirrors segment_error().
 *
 * Decoding repeatedly (bounded) rejects `%252e%252e`, which decodes to `%2e%2e` and then to `..`, and `%252F`,
 * which decodes to `/`: a proxy or CDN that decodes once before forwarding would otherwise turn a URL this
 * accepted into a real traversal. Malformed percent-escapes are refused rather than guessed.
 */
function segmentError(seg: string): string | undefined {
  for (let i = 0; i < MAX_DECODES; i++) {
    if (seg === "." || seg === "..") return "must not contain dot segments";
    if (seg.includes("/") || seg.includes("\\")) return "must not contain encoded path separators";
    if (MALFORMED_PERCENT.test(seg)) return "must not contain a malformed percent-escape";
    let decoded: string;
    try {
      decoded = decodeURIComponent(seg);
    } catch {
      return "must not contain a malformed percent-escape";
    }
    if (decoded === seg) return undefined;
    seg = decoded;
  }
  return "must not be percent-encoded this deeply";
}

/**
 * CIMD client identifier URL rules (draft-ietf-oauth-client-id-metadata-document-02 §3).
 * Mirrored exactly in lambdas/shared/cimd_url.py — see that module's docstring for why the two must agree.
 */
export function validateCimdUrl(value: string): string | undefined {
  if (CONTROL_OR_SPACE.test(value)) return "must not contain control characters or spaces";
  // WHATWG silently rewrites a backslash in the authority to '/', so `https://127.0.0.1\evil.example/x` parses
  // here with host 127.0.0.1 while Python's urlsplit keeps the whole string as the hostname. Rejecting it
  // outright is the only way the two stay in agreement.
  if (value.includes("\\")) return "must not contain a backslash";
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "not a valid URL";
  }
  if (url.protocol !== "https:") return "scheme must be https";
  if (url.username || url.password) return "must not contain userinfo";
  if (!HOST_SYNTAX.test(RAW_AUTHORITY.exec(value)?.[1] ?? "")) {
    return "host must be ASCII (letters, digits, hyphen, dot; use punycode for internationalised names)";
  }
  if (!url.pathname || url.pathname === "/") return "must contain a path component";
  for (const seg of rawPath(value).split("/")) {
    const problem = segmentError(seg);
    if (problem) return problem;
  }
  if (url.search) return "must not contain a query component";
  if (url.hash) return "must not contain a fragment";
  return undefined;
}

export function validateConfig(cfg: Config): void {
  const errors: string[] = [];
  if (!/^[a-z][a-z0-9-]{2,30}$/.test(cfg.project.name)) errors.push("project.name must match ^[a-z][a-z0-9-]{2,30}$");
  if (!/^[a-z0-9]{1,12}$/.test(cfg.project.stage)) errors.push("project.stage must match ^[a-z0-9]{1,12}$");
  if (!!cfg.edge.customDomain !== !!cfg.edge.certificateArnUsEast1) {
    errors.push("edge.customDomain and edge.certificateArnUsEast1 must both be set or both be empty");
  }
  if (cfg.edge.customDomain && !cfg.edge.enabled) errors.push("edge.customDomain requires edge.enabled (custom domains live on CloudFront)");
  if (!!cfg.cognito.customLoginDomain !== !!cfg.cognito.loginCertificateArn) {
    errors.push("cognito.customLoginDomain and cognito.loginCertificateArn must both be set or both be empty");
  }
  if (!/^[\w\s+=,.@-]+$/.test(cfg.cognito.resourceServerName)) errors.push("cognito.resourceServerName violates Cognito's name pattern");
  if (cfg.cognito.loginDomainPrefix) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(cfg.cognito.loginDomainPrefix)) errors.push("cognito.loginDomainPrefix must be 1-63 lowercase alphanumerics or hyphens");
    if (COGNITO_DOMAIN_RESERVED.some((w) => cfg.cognito.loginDomainPrefix.includes(w))) errors.push("cognito.loginDomainPrefix must not contain 'cognito', 'amazon', or 'aws'");
  }
  // Empty is a valid deployment only when the built-in test client is on: the registrar appends that URL at
  // runtime, so the stack still has exactly one registered client and nothing third-party is trusted.
  // `=== true`, not truthiness: CIMD_CONFIG_OVERRIDES is untyped JSON, and the string "false" is truthy here
  // while the registrar enables the test client only when its env value lowercases to "true". Truthiness would
  // waive the allow-list gate for a deployment that then registers nothing at all.
  if (!cfg.cimd.allowedClients.length && cfg.testClient.enabled !== true) {
    const candidates = KNOWN_CIMD_CLIENTS.map((c) => `     ${c.url}   (${c.client})`).join("\n");
    errors.push(
      "cimd.allowedClients is empty. This sample grants the MCP invoke scope only to client identifier URLs you " +
      "list here, so nothing is trusted by default. Paste the URL(s) you intend to trust, for example:\n" +
      `${candidates}\n` +
      "     ChatGPT connectors use a per-connector URL shown in that connector's own settings.\n" +
      "   Or set testClient.enabled = true to deploy with only the built-in test client, which registers itself.",
    );
  }
  for (const c of cfg.cimd.allowedClients) {
    const err = validateCimdUrl(c);
    if (err) errors.push(`cimd.allowedClients entry '${c}': ${err}`);
  }
  // Check the keys explicitly rather than iterating Object.entries: an override of `{}` has no entries, so a
  // loop over what is present would validate nothing and silently synthesise a stage with no route throttle.
  // API Gateway requires integers here, and a fractional value is emitted unchanged and rejected at deploy.
  for (const name of ["throttle", "revalidatingRouteThrottle"] as const) {
    for (const k of ["rateLimit", "burstLimit"] as const) {
      const v = cfg.api[name]?.[k];
      if (!Number.isInteger(v) || !(v > 0)) errors.push(`api.${name}.${k} must be a positive integer`);
    }
  }
  if (cfg.api.revalidatingRouteThrottle?.rateLimit > cfg.api.throttle?.rateLimit
      || cfg.api.revalidatingRouteThrottle?.burstLimit > cfg.api.throttle?.burstLimit) {
    errors.push("api.revalidatingRouteThrottle must not exceed api.throttle (it is a per-route tightening of the stage default)");
  }
  if (cfg.cimd.cacheMinMinutes * 60 >= cfg.cimd.cacheMaxHours * 3600) errors.push("cimd.cacheMinMinutes must be below cimd.cacheMaxHours");
  // Positivity first, and explicitly: NaN satisfies neither `<=` nor `>=`, so it would slip through both
  // relational checks below, reach the registrar as float("NaN") and make the deadline comparison never fire.
  for (const k of ["fetchTimeoutSeconds", "fetchDeadlineSeconds"] as const) {
    if (!Number.isFinite(cfg.cimd[k]) || !(cfg.cimd[k] > 0)) errors.push(`cimd.${k} must be a finite positive number`);
  }
  if (cfg.cimd.fetchDeadlineSeconds <= cfg.cimd.fetchTimeoutSeconds) {
    errors.push("cimd.fetchDeadlineSeconds must exceed cimd.fetchTimeoutSeconds (it is the wall-clock budget for the whole exchange, not one socket read)");
  }
  if (cfg.cimd.fetchDeadlineSeconds >= cfg.cimd.registrarTimeoutSeconds) {
    errors.push("cimd.fetchDeadlineSeconds must be below cimd.registrarTimeoutSeconds so the registrar can still write its result");
  }
  if (cfg.cimd.registrarLockTtlSeconds <= cfg.cimd.registrarTimeoutSeconds * 1.5) errors.push("cimd.registrarLockTtlSeconds must be at least 1.5x cimd.registrarTimeoutSeconds so a crashed run cannot hold a live lock");
  if (cfg.cimd.registrarTimeoutSeconds > 900) errors.push("cimd.registrarTimeoutSeconds exceeds the Lambda maximum");
  if (cfg.cimd.maxStaleHours * 3600 <= cfg.cimd.cacheMaxHours * 3600) errors.push("cimd.maxStaleHours must exceed cimd.cacheMaxHours");
  if (cfg.cognito.accessTokenMinutes < 5 || cfg.cognito.accessTokenMinutes > 1440) errors.push("cognito.accessTokenMinutes must be 5..1440");
  if (cfg.cognito.refreshTokenDays < 1 || cfg.cognito.refreshTokenDays > 3650) errors.push("cognito.refreshTokenDays must be 1..3650");
  if (!cfg.ssmPrefix.startsWith("/") || cfg.ssmPrefix.endsWith("/")) errors.push("ssmPrefix must start with '/' and not end with '/'");
  if (!/^\/test-client\/[A-Za-z0-9._-]+\.json$/.test(cfg.testClient.path) || ["/test-client/index.html", "/test-client/callback"].includes(cfg.testClient.path)) {
    errors.push("testClient.path must be /test-client/<name>.json (only that route reaches the proxy; index.html and callback are reserved)");
  }
  for (const k of ["metadataCacheSeconds", "unavailableRetryAfterSeconds", "cognitoTimeoutSeconds", "consentCookieMaxAgeSeconds", "revalidateTimeoutSeconds"] as const) {
    if (!(cfg.cimd[k] > 0)) errors.push(`cimd.${k} must be positive`);
  }
  if (cfg.cimd.cognitoTimeoutSeconds + cfg.cimd.revalidateTimeoutSeconds >= cfg.runtime.lambdaTimeoutSeconds) {
    errors.push("cimd.cognitoTimeoutSeconds + cimd.revalidateTimeoutSeconds must be below runtime.lambdaTimeoutSeconds (the proxy may do both in one /token call)");
  }
  for (const u of cfg.cognito.demoUsers) {
    if (!cfg.cognito.groups.includes(u.group)) errors.push(`demo user ${u.username} references unknown group ${u.group}`);
  }
  if (errors.length) throw new Error(`Invalid config.ts:\n - ${errors.join("\n - ")}`);
}

const COGNITO_DOMAIN_RESERVED = ["cognito", "amazon", "aws"];

/** Deterministic, collision-resistant Cognito login domain prefix. Cognito forbids the words cognito/amazon/aws in prefixes. */
export function loginDomainPrefix(cfg: Config, account: string): string {
  if (cfg.cognito.loginDomainPrefix) return cfg.cognito.loginDomainPrefix;
  const hash = createHash("sha256").update(`${account}:${cfg.project.region}`).digest("hex").slice(0, 8);
  let base = cfg.project.name;
  for (const word of COGNITO_DOMAIN_RESERVED) base = base.split(word).join("");
  base = base.replace(/-{2,}/g, "-").replace(/^-|-$/g, "") || "mcp";
  return `${base}-${cfg.project.stage}-${hash}`.slice(0, 63);
}

/** Deterministic registrar function name so ApiStack can grant lambda:InvokeFunction without a cross-stack reference cycle. */
export function registrarFunctionName(cfg: Config): string {
  return `${cfg.project.name}-${cfg.project.stage}-registrar`;
}

export function stackName(cfg: Config, role: string): string {
  return `${cfg.project.name}-${cfg.project.stage}-${role}`;
}

/** SSM parameter names read by the Lambdas (static strings; values are written by RegistrationStack). */
export function ssmNames(cfg: Config) {
  const p = cfg.ssmPrefix;
  return {
    publicBaseUrl: `${p}/public_base_url`,
    originBaseUrl: `${p}/origin_base_url`,
    authorizationServerUrl: `${p}/authorization_server_url`,
    resourceUrl: `${p}/resource_url`,
    invokeScope: `${p}/invoke_scope`,
    allowedHosts: `${p}/allowed_hosts`,
  };
}

/** Derived public URLs. `publicBaseUrl` may be a CDK token. */
export function deriveUrls(cfg: Config, originBaseUrl: string, publicHost?: string) {
  const publicBaseUrl = cfg.edge.enabled ? `https://${cfg.edge.customDomain || publicHost}` : originBaseUrl;
  const resourceUrl = `${publicBaseUrl}/mcp`;
  return {
    originBaseUrl,
    publicBaseUrl,
    authorizationServerUrl: publicBaseUrl,
    resourceUrl,
    invokeScope: `${resourceUrl}/${cfg.cognito.scopeName}`,
  };
}

export function cognitoIssuer(region: string, userPoolId: string): string {
  return `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
}
