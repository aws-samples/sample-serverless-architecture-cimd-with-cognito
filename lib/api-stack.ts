import * as cdk from "aws-cdk-lib";
import * as apigwv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";
import type { Config } from "../config";
import { PythonLambda } from "./constructs/python-lambda";
import { cognitoIssuer, registrarFunctionName } from "./derive";

export interface ApiStackProps extends cdk.StackProps {
  cfg: Config;
  userPool: cognito.IUserPool;
  /** Cognito Managed Login base URL (https://<prefix>.auth.<region>.amazoncognito.com or the custom login domain). */
  loginBaseUrl: string;
  table: dynamodb.ITable;
}

/**
 * HTTP API ($default stage, no stage path) in front of the FastMCP resource server and the CIMD proxy.
 * Lambdas never receive URLs as environment variables; they read them from SSM (written by RegistrationStack).
 */
export class ApiStack extends cdk.Stack {
  readonly httpApi: apigwv2.HttpApi;
  readonly mcpServer: PythonLambda;
  readonly cimdProxy: PythonLambda;
  /** https://<api-id>.execute-api.<region>.amazonaws.com (token) */
  readonly originBaseUrl: string;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);
    const { cfg, userPool, loginBaseUrl, table } = props;

    const tokenIssuer = cognitoIssuer(this.region, userPool.userPoolId);
    const commonEnv = {
      SSM_PREFIX: cfg.ssmPrefix,
      SSM_CACHE_SECONDS: String(cfg.runtime.ssmCacheSeconds),
      TABLE_NAME: table.tableName,
    };

    this.mcpServer = new PythonLambda(this, "McpServer", {
      cfg,
      name: "mcp_server",
      handler: "handler.handler",
      environment: {
        ...commonEnv,
        TOKEN_ISSUER: tokenIssuer,
        TOKEN_JWKS_URL: `${tokenIssuer}/.well-known/jwks.json`,
        ENFORCE_REGISTERED_CLIENT: String(cfg.mcp.enforceRegisteredClient),
        REGISTERED_CLIENT_CACHE_SECONDS: String(cfg.mcp.registeredClientCacheSeconds),
        TOOL_NAME: cfg.mcp.toolName,
        TOOL_DESCRIPTION: cfg.mcp.toolDescription,
        REPLY_TEXT: cfg.mcp.replyText,
      },
    });

    this.cimdProxy = new PythonLambda(this, "CimdProxy", {
      cfg,
      name: "cimd_proxy",
      handler: "handler.handler",
      environment: {
        ...commonEnv,
        TOKEN_ISSUER: tokenIssuer,
        // Cognito-owned host, fixed before ApiStack exists: not part of the API -> Lambda -> API cycle the SSM rule prevents.
        COGNITO_LOGIN_BASE_URL: loginBaseUrl,
        COGNITO_TIMEOUT_SECONDS: String(cfg.cimd.cognitoTimeoutSeconds),
        SHOW_CONSENT_INTERSTITIAL: String(cfg.cimd.showConsentInterstitial),
        CONSENT_COOKIE_MAX_AGE_SECONDS: String(cfg.cimd.consentCookieMaxAgeSeconds),
        METADATA_CACHE_SECONDS: String(cfg.cimd.metadataCacheSeconds),
        UNAVAILABLE_RETRY_AFTER_SECONDS: String(cfg.cimd.unavailableRetryAfterSeconds),
        TEST_CLIENT_ENABLED: String(cfg.testClient.enabled),
        TEST_CLIENT_PATH: cfg.testClient.path,
        TEST_CLIENT_NAME: `${cfg.project.name}-${cfg.project.stage} test client`,
        REGISTRAR_FUNCTION_NAME: registrarFunctionName(cfg),
        REVALIDATE_TIMEOUT_SECONDS: String(cfg.cimd.revalidateTimeoutSeconds),
      },
    });
    // Authorization-time freshness: on a stale mapping the proxy synchronously asks the (private) registrar to
    // revalidate and fails closed if it cannot. Static function name avoids an ApiStack <-> RegistrationStack cycle.
    this.cimdProxy.fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ["lambda:InvokeFunction"],
      resources: [`arn:${this.partition}:lambda:${this.region}:${this.account}:function:${registrarFunctionName(cfg)}`],
    }));

    // SSM: GetParametersByPath authorizes against the path resource itself; GetParameter against each parameter.
    const ssmArns = [
      `arn:${this.partition}:ssm:${this.region}:${this.account}:parameter${cfg.ssmPrefix}`,
      `arn:${this.partition}:ssm:${this.region}:${this.account}:parameter${cfg.ssmPrefix}/*`,
    ];
    const ssmRead = new iam.PolicyStatement({ actions: ["ssm:GetParameter", "ssm:GetParametersByPath"], resources: ssmArns });
    this.mcpServer.fn.addToRolePolicy(ssmRead);
    this.cimdProxy.fn.addToRolePolicy(ssmRead);
    if (cfg.mcp.enforceRegisteredClient) {
      this.mcpServer.fn.addToRolePolicy(new iam.PolicyStatement({ actions: ["dynamodb:GetItem"], resources: [table.tableArn] }));
    }
    this.cimdProxy.fn.addToRolePolicy(new iam.PolicyStatement({ actions: ["dynamodb:GetItem", "dynamodb:Query"], resources: [table.tableArn] }));

    const accessLogs = new logs.LogGroup(this, "AccessLogs", {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.httpApi = new apigwv2.HttpApi(this, "HttpApi", {
      apiName: `${cfg.project.name}-${cfg.project.stage}`,
      createDefaultStage: false,
      disableExecuteApiEndpoint: false,
    });
    const stage = new apigwv2.HttpStage(this, "DefaultStage", {
      httpApi: this.httpApi,
      stageName: "$default",
      autoDeploy: true,
      throttle: { rateLimit: cfg.api.throttle.rateLimit, burstLimit: cfg.api.throttle.burstLimit },
    });
    const cfnStage = stage.node.defaultChild as apigwv2.CfnStage;
    cfnStage.accessLogSettings = {
      destinationArn: accessLogs.logGroupArn,
      format: JSON.stringify({
        requestId: "$context.requestId", routeKey: "$context.routeKey", status: "$context.status",
        latencyMs: "$context.responseLatency", ip: "$context.identity.sourceIp", error: "$context.error.message",
      }),
    };
    // Every unauthenticated route that can cause outbound work is throttled below the stage default, so the
    // amplification cannot be driven from the internet. On a stale mapping the proxy invokes the registrar
    // synchronously, which fetches the CIMD document and possibly its JWKS; all three routes below reach that
    // path before any credential is checked (/token resolves the mapping before validating the grant), so
    // throttling only /authorize would leave the same amplification reachable through /token. A mitigation, not
    // a WAF substitute: see README §2 "Rate limiting and WAF" before exposing the API publicly.
    //
    // addPropertyOverride, not `cfnStage.routeSettings = …`: RouteSettings is a map with arbitrary keys, and
    // aws-cdk-lib passes its values through untransformed, so assigning the typed camelCase form synthesises
    // `throttlingRateLimit` and CloudFormation ignores it. The override writes the CloudFormation casing.
    const revalidating = {
      ThrottlingRateLimit: cfg.api.revalidatingRouteThrottle.rateLimit,
      ThrottlingBurstLimit: cfg.api.revalidatingRouteThrottle.burstLimit,
    };
    cfnStage.addPropertyOverride("RouteSettings", {
      "GET /authorize": revalidating,
      "POST /consent": revalidating,
      "POST /token": revalidating,
    });

    const mcpIntegration = new integrations.HttpLambdaIntegration("McpIntegration", this.mcpServer.fn);
    const proxyIntegration = new integrations.HttpLambdaIntegration("ProxyIntegration", this.cimdProxy.fn);
    const M = apigwv2.HttpMethod;

    // Explicit routes only; no $default catch-all.
    this.httpApi.addRoutes({ path: "/mcp", methods: [M.ANY], integration: mcpIntegration });
    this.httpApi.addRoutes({ path: "/.well-known/oauth-protected-resource/{proxy+}", methods: [M.GET], integration: mcpIntegration });
    this.httpApi.addRoutes({ path: "/.well-known/oauth-authorization-server", methods: [M.GET], integration: proxyIntegration });
    this.httpApi.addRoutes({ path: "/.well-known/openid-configuration", methods: [M.GET], integration: proxyIntegration });
    const throttledRoutes = [
      ...this.httpApi.addRoutes({ path: "/authorize", methods: [M.GET], integration: proxyIntegration }),
      ...this.httpApi.addRoutes({ path: "/consent", methods: [M.POST], integration: proxyIntegration }),
      ...this.httpApi.addRoutes({ path: "/token", methods: [M.POST], integration: proxyIntegration }),
    ];
    this.httpApi.addRoutes({ path: "/revoke", methods: [M.POST], integration: proxyIntegration });
    // RouteSettings keys are validated by the service, not just stored: creating the stage before the routes it
    // names fails with "Unable to find Route by key GET /authorize". Nothing in the template references the
    // routes from the stage (the keys are plain strings), so CloudFormation is free to order the stage first —
    // which is exactly what happens on a first deploy into an empty account. The dependency is one-way: routes
    // depend on the Api, never on the Stage, so this adds no cycle.
    for (const route of throttledRoutes) cfnStage.node.addDependency(route);
    if (cfg.testClient.enabled) {
      this.httpApi.addRoutes({ path: "/test-client/{proxy+}", methods: [M.GET], integration: proxyIntegration });
    }

    this.originBaseUrl = `https://${this.httpApi.apiId}.execute-api.${this.region}.${this.urlSuffix}`;
    new cdk.CfnOutput(this, "OriginBaseUrl", { value: this.originBaseUrl });
  }
}
