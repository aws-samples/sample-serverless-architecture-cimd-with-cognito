import { readFileSync } from "fs";
import { join } from "path";
import { validateCimdUrl, validateConfig, loginDomainPrefix } from "../../lib/derive";
import { config, KNOWN_CIMD_CLIENTS } from "../../config";

/** The shipped defaults plus one allow-listed client: the smallest configuration an operator can deploy. */
const deployable = { ...config, cimd: { ...config.cimd, allowedClients: [KNOWN_CIMD_CLIENTS[0].url] } };

describe("config validation", () => {
  test("defaults plus one allow-listed client are valid", () => expect(() => validateConfig(deployable)).not.toThrow());

  describe("nothing is trusted by default", () => {
    test("the shipped defaults refuse to synth because the allow-list is empty", () => {
      expect(config.cimd.allowedClients).toEqual([]);
      expect(() => validateConfig(config)).toThrow(/cimd.allowedClients is empty/);
    });
    test("the error names the candidate URLs so the operator can paste one deliberately", () => {
      expect(() => validateConfig(config)).toThrow(new RegExp(KNOWN_CIMD_CLIENTS[0].url));
    });
    test("an empty allow-list is allowed when only the self-registering test client is enabled", () => {
      const testClientOnly = { ...config, testClient: { ...config.testClient, enabled: true } };
      expect(() => validateConfig(testClientOnly)).not.toThrow();
    });
  });

  test.each([
    ["https://claude.ai/oauth/mcp-oauth-client-metadata", undefined],
    ["http://claude.ai/oauth/x", "scheme must be https"],
    ["https://claude.ai", "must contain a path component"],
    ["https://claude.ai/", "must contain a path component"],
    ["https://user@claude.ai/x", "must not contain userinfo"],
    ["https://claude.ai/a/../b", "must not contain dot segments"],
    ["https://claude.ai/a/%2e%2e/b", "must not contain dot segments"],
    ["https://claude.ai/%2E/b", "must not contain dot segments"],
    // Double-encoded: a proxy or CDN that decodes once before forwarding would hand on a real traversal.
    ["https://claude.ai/a/%252e%252e/b", "must not contain dot segments"],
    ["https://claude.ai/a/%25252e/b", "must not contain dot segments"],
    ["https://claude.ai:8443/oauth/x", undefined],
    ["https://claude.ai/x?y=1", "must not contain a query component"],
    ["https://claude.ai/x#frag", "must not contain a fragment"],
  ])("CIMD URL rule: %s", (url, expected) => expect(validateCimdUrl(url)).toBe(expected));

  // Shared verdict table, also asserted by tests/unit/test_cimd_url.py against lambdas/shared/cimd_url.py.
  // A URL the two disagree on is either a deployment whose synth-time allow-list check refuses a URL the
  // registrar would accept, or the reverse. Regenerate with tests/fixtures/gen_cases.py, which refuses to write
  // the table while the two implementations differ.
  const verdicts: { url: string; verdict: "accept" | "reject" }[] =
    JSON.parse(readFileSync(join(__dirname, "..", "fixtures", "cimd-url-verdicts.json"), "utf8")).cases;
  test.each(verdicts.map((c) => [c.url, c.verdict] as const))(
    "agrees with the Python mirror: %j -> %s",
    (url, verdict) => expect(validateCimdUrl(url) === undefined ? "accept" : "reject").toBe(verdict),
  );
  test("edge custom domain requires certificate and edge.enabled", () => {
    const bad = { ...deployable, edge: { ...deployable.edge, customDomain: "mcp.example.com" } };
    expect(() => validateConfig(bad)).toThrow(/certificateArnUsEast1|edge.enabled/);
  });
  test.each([
    ["/test-client/metadata.json", true],
    ["/test-client/my-client.json", true],
    ["/test-client/callback", false],
    ["/test-client/index.html", false],
    ["/other/metadata.json", false],
    ["/test-client/metadata", false],
  ])("testClient.path %s valid=%s", (path, ok) => {
    const cfg = { ...deployable, testClient: { ...deployable.testClient, path } };
    if (ok) expect(() => validateConfig(cfg)).not.toThrow();
    else expect(() => validateConfig(cfg)).toThrow(/testClient.path/);
  });
  describe("per-route throttle on the revalidating routes", () => {
    test("may only tighten the stage throttle", () => {
      const bad = { ...deployable, api: { ...deployable.api, revalidatingRouteThrottle: { rateLimit: 500, burstLimit: 1000 } } };
      expect(() => validateConfig(bad)).toThrow(/revalidatingRouteThrottle must not exceed/);
    });
    // An override of {} has no entries, so validating only the keys that are present would pass and silently
    // synthesise a stage with no route throttle at all.
    test("a partial or empty override is rejected, not silently dropped", () => {
      for (const partial of [{}, { rateLimit: 5 }, { burstLimit: 10 }]) {
        const bad = { ...deployable, api: { ...deployable.api, revalidatingRouteThrottle: partial as never } };
        expect(() => validateConfig(bad)).toThrow(/must be a positive integer/);
      }
    });
    test("fractional and non-positive limits are rejected: API Gateway requires integers", () => {
      for (const v of [0.5, 0, -1, NaN]) {
        const bad = { ...deployable, api: { ...deployable.api, revalidatingRouteThrottle: { rateLimit: v, burstLimit: 10 } } };
        expect(() => validateConfig(bad)).toThrow(/must be a positive integer/);
      }
    });
  });
  describe("guarded fetch deadline", () => {
    test("must sit between the socket timeout and the registrar timeout", () => {
      const tooSmall = { ...deployable, cimd: { ...deployable.cimd, fetchDeadlineSeconds: 3 } };
      expect(() => validateConfig(tooSmall)).toThrow(/fetchDeadlineSeconds must exceed/);
      const tooBig = { ...deployable, cimd: { ...deployable.cimd, fetchDeadlineSeconds: 300 } };
      expect(() => validateConfig(tooBig)).toThrow(/below cimd.registrarTimeoutSeconds/);
    });
    // NaN satisfies neither `<=` nor `>=`, so relational checks alone let it through to the registrar, where
    // float("NaN") makes the deadline comparison never fire and the fetch is effectively unbounded again.
    test.each([[NaN], [-1], [0], [Infinity]])("rejects the non-finite or non-positive value %p", (v) => {
      const bad = { ...deployable, cimd: { ...deployable.cimd, fetchDeadlineSeconds: v } };
      expect(() => validateConfig(bad)).toThrow(/must be a finite positive number|fetchDeadlineSeconds/);
    });
  });
  test("an untyped testClient.enabled override cannot waive the allow-list gate", () => {
    // CIMD_CONFIG_OVERRIDES is JSON, so "false" reaches validateConfig as a truthy string while the registrar
    // enables the test client only when its env value lowercases to "true".
    const bad = { ...config, testClient: { ...config.testClient, enabled: "false" as never } };
    expect(() => validateConfig(bad)).toThrow(/cimd.allowedClients is empty/);
  });
  test("proxy relay and revalidate timeouts must fit inside the Lambda timeout", () => {
    const bad = { ...deployable, cimd: { ...deployable.cimd, cognitoTimeoutSeconds: 20, revalidateTimeoutSeconds: 15 } };
    expect(() => validateConfig(bad)).toThrow(/lambdaTimeoutSeconds/);
  });
  test("lock TTL must exceed registrar timeout", () => {
    const bad = { ...deployable, cimd: { ...deployable.cimd, registrarLockTtlSeconds: 300, registrarTimeoutSeconds: 300 } };
    expect(() => validateConfig(bad)).toThrow(/registrarLockTtlSeconds/);
  });
  test("login domain prefix is deterministic and collision-resistant", () => {
    const a = loginDomainPrefix(config, "111111111111");
    const b = loginDomainPrefix(config, "222222222222");
    expect(a).toMatch(new RegExp(`^cimd-mcp-${config.project.stage}-[0-9a-f]{8}$`)); // 'cognito' stripped: reserved word in Cognito domain prefixes
    expect(a).not.toMatch(/cognito|amazon|aws/);
    expect(a).not.toBe(b);
    expect(loginDomainPrefix(config, "111111111111")).toBe(a);
  });
});
