/**
 * Single source of every configurable value. Nothing in lib/, bin/, or lambdas/ may hard-code
 * a region, account, URL, hostname, ARN, resource name, lifetime, or toggle. Dependency versions
 * live in pyproject.toml + uv.lock and package.json, never here. Validation rules are in lib/derive.ts (validateConfig).
 */
export interface Config {
  project: { name: string; stage: string; region: string };
  iam: { permissionsBoundaryArn: string };
  api: {
    throttle: { rateLimit: number; burstLimit: number };
    /**
     * Per-route override for every unauthenticated route that can cause outbound work. On a stale mapping the
     * proxy calls the registrar synchronously, which fetches the client's CIMD document and possibly its JWKS.
     * Three routes reach that path, all before any credential is checked: `GET /authorize` and `POST /consent`
     * via _validated_authorize, and `POST /token`, which resolves the mapping before it validates the grant.
     * Throttling only /authorize would leave the same amplification reachable through /token.
     * Kept below api.throttle so the rest of the API is unaffected. API Gateway throttling is not a WAF
     * substitute; see README §2 "Rate limiting and WAF".
     */
    revalidatingRouteThrottle: { rateLimit: number; burstLimit: number };
  };
  edge: {
    enabled: boolean;
    customDomain: string;
    certificateArnUsEast1: string;
    wafRateLimitPer5Min: number;
    wafManagedRuleGroups: string[];
    originProtection: "oac" | "header";
  };
  cognito: {
    loginDomainPrefix: string;
    customLoginDomain: string;
    loginCertificateArn: string;
    resourceServerName: string;
    scopeName: string;
    accessTokenMinutes: number;
    refreshTokenDays: number;
    createDemoUsers: boolean;
    demoUsers: { username: string; email: string; group: string }[];
    groups: string[];
  };
  cimd: {
    /**
     * The only client identifier URLs that ever receive a Cognito app client. Empty by default on purpose:
     * a deploy must not grant any third party the invoke scope until an operator has pasted the URL here
     * deliberately. validateConfig rejects an empty list and prints the known candidates.
     */
    allowedClients: string[];
    fetchTimeoutSeconds: number;
    fetchDeadlineSeconds: number;      // total wall-clock budget for one guarded fetch; a slow-drip server cannot outlast it
    maxDocumentBytes: number;
    cacheMinMinutes: number;
    cacheMaxHours: number;
    registrarSchedule: string;
    registrarLockTtlSeconds: number;      // must exceed runtime.registrarTimeoutSeconds
    registrarTimeoutSeconds: number;
    maxJwksBytes: number;
    maxStaleHours: number;                // disable a client whose document could not be revalidated for this long
    revalidateLockWaitSeconds: number;    // proxy-triggered revalidation waits this long for the registrar lock, then fails closed
    revalidateTimeoutSeconds: number;     // proxy's client-side timeout for the synchronous registrar invoke
    showConsentInterstitial: boolean;
    consentCookieMaxAgeSeconds: number;
    metadataCacheSeconds: number;         // Cache-Control max-age on RFC 8414 metadata and the test-client CIMD document
    unavailableRetryAfterSeconds: number; // Retry-After when the proxy fails closed (temporarily_unavailable)
    cognitoTimeoutSeconds: number;        // proxy's client-side timeout for the Cognito /oauth2/token and /oauth2/revoke relay
  };
  mcp: {
    toolName: string;
    toolDescription: string;
    replyText: string;
    enforceRegisteredClient: boolean;
    /**
     * SECURITY PARAMETER, not a performance knob. Upper bound on how long the MCP server may keep serving a
     * client that the registrar has just disabled or rotated: the registered-client lookup is read strongly
     * consistent, but the per-container positive cache is only re-checked after this many seconds. Lower it to
     * shorten that window (more DynamoDB reads per invocation); 0 disables caching entirely.
     */
    registeredClientCacheSeconds: number;
  };
  devFixtures: { preRegisteredClient: boolean; callbackPort: number };
  testClient: { enabled: boolean; path: string };
  runtime: {
    pythonVersion: "3.12";
    lambdaMemoryMb: number;
    lambdaTimeoutSeconds: number;
    logRetentionDays: number;
    ssmCacheSeconds: number;
    logLevel: "DEBUG" | "INFO" | "WARNING";
  };
  ssmPrefix: string;
}

/**
 * Client identifier URLs published by the MCP clients this sample has been verified against. Reference data for
 * the operator, NOT an allow-list: nothing here is trusted until it is copied into cimd.allowedClients.
 * ChatGPT's URL is per-connector (shown in the connector's own settings), so it cannot be listed here.
 */
export const KNOWN_CIMD_CLIENTS: { client: string; url: string }[] = [
  { client: "claude.ai web, Claude Desktop, Claude mobile, Cowork", url: "https://claude.ai/oauth/mcp-oauth-client-metadata" },
];

const defaults: Config = {
  project: { name: "cimd-cognito-mcp", stage: "dev", region: "ap-southeast-2" },
  iam: { permissionsBoundaryArn: "" },
  api: {
    throttle: { rateLimit: 50, burstLimit: 100 },
    revalidatingRouteThrottle: { rateLimit: 10, burstLimit: 20 },
  },
  edge: {
    enabled: false,
    customDomain: "",
    certificateArnUsEast1: "",
    wafRateLimitPer5Min: 1000,
    wafManagedRuleGroups: ["AWSManagedRulesCommonRuleSet"],
    originProtection: "header",
  },
  cognito: {
    loginDomainPrefix: "",
    customLoginDomain: "",
    loginCertificateArn: "",
    resourceServerName: "mcp-server",
    scopeName: "invoke",
    accessTokenMinutes: 15,
    refreshTokenDays: 30,
    createDemoUsers: false,
    demoUsers: [{ username: "demo", email: "demo@example.com", group: "mcp-users" }],
    groups: ["mcp-users"],
  },
  cimd: {
    // Deliberately empty: paste the client identifier URLs you intend to trust. See KNOWN_CIMD_CLIENTS below
    // for the URLs published by the clients this sample has been verified against.
    allowedClients: [],
    fetchTimeoutSeconds: 3,
    fetchDeadlineSeconds: 6,
    maxDocumentBytes: 5120,
    cacheMinMinutes: 5,
    cacheMaxHours: 24,
    registrarSchedule: "rate(1 hour)",
    registrarLockTtlSeconds: 900,
    registrarTimeoutSeconds: 300,
    maxJwksBytes: 12288,
    maxStaleHours: 72,
    revalidateLockWaitSeconds: 3,
    revalidateTimeoutSeconds: 8,
    showConsentInterstitial: true,
    consentCookieMaxAgeSeconds: 300,
    metadataCacheSeconds: 300,
    unavailableRetryAfterSeconds: 10,
    cognitoTimeoutSeconds: 10,
  },
  mcp: {
    toolName: "echo_hello",
    toolDescription: "Confirms that the MCP tool was invoked through Cognito + CIMD authorization.",
    replyText: "Tool invoked successfully via Cognito + CIMD",
    enforceRegisteredClient: true,
    registeredClientCacheSeconds: 60,
  },
  devFixtures: { preRegisteredClient: false, callbackPort: 8767 },
  testClient: { enabled: false, path: "/test-client/metadata.json" },
  runtime: {
    pythonVersion: "3.12",
    lambdaMemoryMb: 512,
    lambdaTimeoutSeconds: 30,
    logRetentionDays: 30,
    ssmCacheSeconds: 300,
    logLevel: "INFO",
  },
  ssmPrefix: "/cimd-cognito-mcp/dev",
};

/** Optional shallow per-top-level-key overrides for CI: CIMD_CONFIG_OVERRIDES='{"devFixtures":{"preRegisteredClient":true}}' */
function applyOverrides(base: Config): Config {
  const raw = process.env.CIMD_CONFIG_OVERRIDES;
  if (!raw) return base;
  const overrides = JSON.parse(raw) as Partial<Record<keyof Config, unknown>>;
  const merged: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(overrides)) {
    const current = merged[key];
    merged[key] = typeof current === "object" && current !== null && !Array.isArray(current)
      ? { ...(current as object), ...(value as object) }
      : value;
  }
  return merged as unknown as Config;
}

export const config: Config = applyOverrides(defaults);
