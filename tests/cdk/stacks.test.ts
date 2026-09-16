import * as cdk from "aws-cdk-lib";
import { Annotations, Match, Template } from "aws-cdk-lib/assertions";
import { AwsSolutionsChecks } from "cdk-nag";
import { config, Config } from "../../config";
import { ApiStack } from "../../lib/api-stack";
import { DataStack } from "../../lib/data-stack";
import { RegistrationStack } from "../../lib/registration-stack";
import { UserPoolStack } from "../../lib/user-pool-stack";
import { applyNagSuppressions } from "../../lib/nag-suppressions";

function synth(overrides: Partial<Config> = {}) {
  const cfg: Config = { ...config, ...overrides, project: { ...config.project, ...(overrides.project ?? {}) } };
  const app = new cdk.App({ context: { "aws:cdk:bundling-stacks": [] } }); // skip Python bundling in unit tests
  const env = { account: "111111111111", region: cfg.project.region };
  const up = new UserPoolStack(app, "up", { cfg, env });
  const data = new DataStack(app, "data", { cfg, env });
  const api = new ApiStack(app, "api", { cfg, env, userPool: up.userPool, loginBaseUrl: up.domain.baseUrl(), table: data.table });
  const reg = new RegistrationStack(app, "reg", { cfg, env, userPool: up.userPool, table: data.table, originBaseUrl: api.originBaseUrl });
  const stacks = [up, data, api, reg];
  applyNagSuppressions({ userPool: up, api, registration: reg, others: [data] });
  cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  app.synth();
  return { app, cfg, up, data, api, reg, stacks };
}

describe("default profile", () => {
  const { api, reg, up, data, stacks, cfg } = synth();

  test("HTTP API has exactly one stage and it is $default", () => {
    const t = Template.fromStack(api);
    t.resourceCountIs("AWS::ApiGatewayV2::Stage", 1);
    t.hasResourceProperties("AWS::ApiGatewayV2::Stage", { StageName: "$default", AutoDeploy: true });
  });

  // Every route that reaches Freshness.fresh_mapping before checking a credential must be throttled, not just
  // /authorize: /token resolves the mapping before it validates the grant, so throttling /authorize alone would
  // leave the same registrar amplification reachable through /token.
  test("every route that can trigger a registrar revalidation is throttled below the stage default", () => {
    const expected = {
      ThrottlingRateLimit: cfg.api.revalidatingRouteThrottle.rateLimit,
      ThrottlingBurstLimit: cfg.api.revalidatingRouteThrottle.burstLimit,
    };
    Template.fromStack(api).hasResourceProperties("AWS::ApiGatewayV2::Stage", {
      DefaultRouteSettings: {
        ThrottlingRateLimit: cfg.api.throttle.rateLimit,
        ThrottlingBurstLimit: cfg.api.throttle.burstLimit,
      },
      // CloudFormation casing asserted deliberately: aws-cdk-lib passes RouteSettings map values through
      // untransformed, so a typed camelCase assignment synthesises keys CloudFormation silently ignores.
      RouteSettings: {
        "GET /authorize": expected,
        "POST /consent": expected,
        "POST /token": expected,
      },
    });
    expect(cfg.api.revalidatingRouteThrottle.rateLimit).toBeLessThan(cfg.api.throttle.rateLimit);
  });

  // A RouteSettings key is validated against the live API, not merely stored: a stage created before the route
  // it names fails with "Unable to find Route by key GET /authorize". Nothing in the template references those
  // routes from the stage, so without an explicit DependsOn CloudFormation may order the stage first — which is
  // what a first deploy into an empty account does. Assert the edge exists for every throttled route key.
  test("the stage depends on every route named in RouteSettings", () => {
    const t = Template.fromStack(api);
    const stage = Object.values(t.findResources("AWS::ApiGatewayV2::Stage"))[0] as any;
    const routeKeys: string[] = Object.keys(stage.Properties.RouteSettings);
    const dependsOn: string[] = stage.DependsOn ?? [];
    const routes = t.findResources("AWS::ApiGatewayV2::Route");
    const dependedRouteKeys = dependsOn
      .filter((id) => id in routes)
      .map((id) => (routes[id] as any).Properties.RouteKey);
    expect(routeKeys.length).toBeGreaterThan(0);
    expect(dependedRouteKeys.sort()).toEqual(routeKeys.sort());
  });

  test("no Lambda environment variable contains a URL host", () => {
    const fns = Template.fromStack(api).findResources("AWS::Lambda::Function");
    for (const fn of Object.values(fns)) {
      const vars = (fn as any).Properties?.Environment?.Variables ?? {};
      const json = JSON.stringify(vars);
      expect(json).not.toMatch(/execute-api|cloudfront\.net/);
    }
  });

  test("cimd-proxy receives the Cognito login domain and proxy settings, but no API URL", () => {
    const fns = Template.fromStack(api).findResources("AWS::Lambda::Function", { Properties: { Handler: "handler.handler" } });
    const proxy = Object.values(fns).find((f: any) => f.Properties.Environment.Variables.COGNITO_LOGIN_BASE_URL) as any;
    expect(proxy).toBeDefined();
    const vars = proxy.Properties.Environment.Variables;
    expect(vars.REGISTRAR_FUNCTION_NAME).toBe("cimd-cognito-mcp-dev-registrar");
    expect(vars.TEST_CLIENT_ENABLED).toBe("false");
    for (const k of ["METADATA_CACHE_SECONDS", "UNAVAILABLE_RETRY_AFTER_SECONDS", "COGNITO_TIMEOUT_SECONDS", "CONSENT_COOKIE_MAX_AGE_SECONDS"]) {
      expect(Number(vars[k])).toBeGreaterThan(0);
    }
    expect(Object.keys(vars).some((k) => /PUBLIC_BASE_URL|RESOURCE_URL|AUTHORIZATION_SERVER_URL/.test(k))).toBe(false);
  });

  test("registrar learns about the test client through env flags, not a URL", () => {
    const fns = Template.fromStack(reg).findResources("AWS::Lambda::Function", { Properties: { FunctionName: "cimd-cognito-mcp-dev-registrar" } });
    const vars = (Object.values(fns)[0] as any).Properties.Environment.Variables;
    expect(vars.TEST_CLIENT_ENABLED).toBe("false");
    expect(vars.TEST_CLIENT_PATH).toBe("/test-client/metadata.json");
  });

  test("test client route exists only when enabled", () => {
    const routesOf = (stack: cdk.Stack) => Object.values(Template.fromStack(stack).findResources("AWS::ApiGatewayV2::Route")).map((r: any) => r.Properties.RouteKey);
    expect(routesOf(api)).not.toContain("GET /test-client/{proxy+}");
    const on = synth({ testClient: { enabled: true, path: "/test-client/metadata.json" } });
    expect(routesOf(on.api)).toContain("GET /test-client/{proxy+}");
  });

  test("explicit routes only, no $default route", () => {
    const routes = Object.values(Template.fromStack(api).findResources("AWS::ApiGatewayV2::Route")).map((r: any) => r.Properties.RouteKey);
    expect(routes).toEqual(expect.arrayContaining(["ANY /mcp", "GET /.well-known/oauth-protected-resource/{proxy+}", "GET /authorize", "POST /token"]));
    expect(routes).not.toContain("$default");
  });

  test("SSM policy covers the prefix ARN and prefix/*", () => {
    const policies = Template.fromStack(api).findResources("AWS::IAM::Policy");
    const statements = Object.values(policies).flatMap((p: any) => p.Properties.PolicyDocument.Statement);
    const ssm = statements.filter((st: any) => JSON.stringify(st.Action).includes("ssm:GetParametersByPath"));
    expect(ssm.length).toBeGreaterThan(0);
    for (const st of ssm) {
      const res = JSON.stringify(st.Resource);
      expect(res).toMatch(/:parameter\/cimd-cognito-mcp\/dev"/);      // the path resource itself
      expect(res).toMatch(/:parameter\/cimd-cognito-mcp\/dev\/\*"/);  // and its children
    }
  });

  test("resource server identifier is the resourceUrl and name is config", () => {
    Template.fromStack(reg).hasResourceProperties("AWS::Cognito::UserPoolResourceServer", {
      Name: config.cognito.resourceServerName,
      Scopes: [{ ScopeName: config.cognito.scopeName, ScopeDescription: Match.anyValue() }],
    });
  });

  test("user pool is Essentials with managed login v2 and no self sign-up", () => {
    const t = Template.fromStack(up);
    t.hasResourceProperties("AWS::Cognito::UserPool", { UserPoolTier: "ESSENTIALS", AdminCreateUserConfig: { AllowAdminCreateUserOnly: true } });
    t.hasResourceProperties("AWS::Cognito::UserPoolDomain", { ManagedLoginVersion: 2 });
  });

  test("table uses pk, on-demand, PITR, TTL", () => {
    Template.fromStack(data).hasResourceProperties("AWS::DynamoDB::Table", {
      KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }], BillingMode: "PAY_PER_REQUEST",
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true }, TimeToLiveSpecification: { AttributeName: "ttl", Enabled: true },
    });
  });

  test("cdk-nag: no unsuppressed errors", () => {
    for (const s of stacks) {
      const errors = Annotations.fromStack(s).findError("*", Match.stringLikeRegexp("AwsSolutions-.*"));
      expect(errors.map((e) => `${e.id}: ${JSON.stringify(e.entry.data)}`)).toEqual([]);
    }
  });
});

describe("registrar", () => {
  const { reg, api } = synth();
  test("has schedule, custom resource run, and scoped Cognito permissions", () => {
    const t = Template.fromStack(reg);
    t.resourceCountIs("AWS::Events::Rule", 1);
    t.hasResourceProperties("Custom::CimdRegistrarRun", { configHash: Match.stringLikeRegexp("^[0-9a-f]{64}$") });
    const statements = Object.values(t.findResources("AWS::IAM::Policy")).flatMap((p: any) => p.Properties.PolicyDocument.Statement);
    const cog = statements.find((st: any) => JSON.stringify(st.Action).includes("cognito-idp:CreateUserPoolClient"));
    expect(cog).toBeDefined();
    expect(cog.Action).toEqual(expect.arrayContaining(["cognito-idp:CreateManagedLoginBranding", "cognito-idp:DeleteManagedLoginBranding", "cognito-idp:DescribeManagedLoginBrandingByClient"]));
    expect(JSON.stringify(cog.Resource)).toMatch(/UserPool.*Arn/);
    expect(JSON.stringify(cog.Resource)).not.toContain('"*"');
  });
  test("registrar has the deterministic name and the proxy may invoke only it", () => {
    Template.fromStack(reg).hasResourceProperties("AWS::Lambda::Function", { FunctionName: "cimd-cognito-mcp-dev-registrar" });
    const statements = Object.values(Template.fromStack(api).findResources("AWS::IAM::Policy")).flatMap((p: any) => p.Properties.PolicyDocument.Statement);
    const inv = statements.filter((st: any) => JSON.stringify(st.Action).includes("lambda:InvokeFunction"));
    expect(inv).toHaveLength(1);
    expect(JSON.stringify(inv[0].Resource)).toContain("function:cimd-cognito-mcp-dev-registrar");
  });
  test("registrar is not reachable through the API", () => {
    const routes = Object.values(Template.fromStack(reg).findResources("AWS::ApiGatewayV2::Route"));
    expect(routes).toHaveLength(0);
  });
});

describe("dev fixture", () => {
  test("creates a public app client and mapping row when enabled", () => {
    const { reg } = synth({ devFixtures: { preRegisteredClient: true, callbackPort: 8767 } });
    const t = Template.fromStack(reg);
    t.hasResourceProperties("AWS::Cognito::UserPoolClient", { GenerateSecret: false, AllowedOAuthFlows: ["code"] });
    t.resourceCountIs("AWS::Cognito::ManagedLoginBranding", 1);
  });
});
