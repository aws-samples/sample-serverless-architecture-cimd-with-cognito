import * as cdk from "aws-cdk-lib";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as cr from "aws-cdk-lib/custom-resources";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as ssm from "aws-cdk-lib/aws-ssm";
import { createHash } from "crypto";
import { Construct } from "constructs";
import type { Config } from "../config";
import { PythonLambda } from "./constructs/python-lambda";
import { deriveUrls, registrarFunctionName, ssmNames } from "./derive";

export interface RegistrationStackProps extends cdk.StackProps {
  cfg: Config;
  userPool: cognito.IUserPool;
  table: dynamodb.ITable;
  originBaseUrl: string;
  /** CloudFront domain when edge.enabled and no custom domain */
  publicHost?: string;
}

/**
 * Always the last stack: it knows the final public URL. Writes the derived URLs to SSM, creates the
 * Cognito resource server whose identifier is resourceUrl, and hosts the registrar.
 */
export class RegistrationStack extends cdk.Stack {
  readonly resourceServer: cognito.UserPoolResourceServer;
  readonly resourceUrl: string;
  readonly invokeScope: string;
  readonly registrar: PythonLambda;
  readonly registrarProvider: cr.Provider;

  constructor(scope: Construct, id: string, props: RegistrationStackProps) {
    super(scope, id, props);
    const { cfg, userPool, table } = props;
    const urls = deriveUrls(cfg, props.originBaseUrl, props.publicHost);
    const names = ssmNames(cfg);
    this.resourceUrl = urls.resourceUrl;
    this.invokeScope = urls.invokeScope;

    const originHost = cdk.Fn.select(2, cdk.Fn.split("/", props.originBaseUrl));
    const allowedHosts = cfg.edge.enabled
      ? cdk.Fn.join(",", [originHost, cdk.Fn.select(2, cdk.Fn.split("/", urls.publicBaseUrl))])
      : originHost;

    const params: Record<string, string> = {
      [names.publicBaseUrl]: urls.publicBaseUrl,
      [names.originBaseUrl]: urls.originBaseUrl,
      [names.authorizationServerUrl]: urls.authorizationServerUrl,
      [names.resourceUrl]: urls.resourceUrl,
      [names.invokeScope]: urls.invokeScope,
      [names.allowedHosts]: allowedHosts,
    };
    Object.entries(params).forEach(([parameterName, stringValue], i) => {
      new ssm.StringParameter(this, `Param${i}`, { parameterName, stringValue, tier: ssm.ParameterTier.STANDARD });
    });

    // Cognito resource server: identifier MUST be a URL for resource binding; the name has its own regex.
    this.resourceServer = new cognito.UserPoolResourceServer(this, "ResourceServer", {
      userPool,
      userPoolResourceServerName: cfg.cognito.resourceServerName,
      identifier: urls.resourceUrl,
      scopes: [new cognito.ResourceServerScope({ scopeName: cfg.cognito.scopeName, scopeDescription: "Invoke MCP tools" })],
    });

    const params_ = Object.values(this.node.children).filter((c) => c instanceof ssm.StringParameter) as ssm.StringParameter[];

    // ---- Registrar: pre-registers allow-listed CIMD URLs as shadow app clients. Private: no API route.
    this.registrar = new PythonLambda(this, "Registrar", {
      cfg,
      name: "registrar",
      handler: "handler.handler",
      functionName: registrarFunctionName(cfg),
      memoryMb: 512,
      timeoutSeconds: cfg.cimd.registrarTimeoutSeconds,
      environment: {
        SSM_PREFIX: cfg.ssmPrefix,
        SSM_CACHE_SECONDS: "0",
        TABLE_NAME: table.tableName,
        USER_POOL_ID: userPool.userPoolId,
        ALLOWED_CLIENTS: JSON.stringify(cfg.cimd.allowedClients),
        ACCESS_TOKEN_MINUTES: String(cfg.cognito.accessTokenMinutes),
        REFRESH_TOKEN_DAYS: String(cfg.cognito.refreshTokenDays),
        FETCH_TIMEOUT_SECONDS: String(cfg.cimd.fetchTimeoutSeconds),
        FETCH_DEADLINE_SECONDS: String(cfg.cimd.fetchDeadlineSeconds),
        MAX_DOCUMENT_BYTES: String(cfg.cimd.maxDocumentBytes),
        CACHE_MIN_SECONDS: String(cfg.cimd.cacheMinMinutes * 60),
        CACHE_MAX_SECONDS: String(cfg.cimd.cacheMaxHours * 3600),
        LOCK_TTL_SECONDS: String(cfg.cimd.registrarLockTtlSeconds),
        LOCK_WAIT_SECONDS: String(Math.max(30, cfg.cimd.registrarTimeoutSeconds - 60)),
        MAX_JWKS_BYTES: String(cfg.cimd.maxJwksBytes),
        MAX_STALE_SECONDS: String(cfg.cimd.maxStaleHours * 3600),
        REVALIDATE_LOCK_WAIT_SECONDS: String(cfg.cimd.revalidateLockWaitSeconds),
        CLIENT_NAME_PREFIX: `${cfg.project.name}-${cfg.project.stage}`,
        // Built-in test client: its CIMD URL is publicBaseUrl + path, known only at runtime (SSM), so the registrar appends it.
        TEST_CLIENT_ENABLED: String(cfg.testClient.enabled),
        TEST_CLIENT_PATH: cfg.testClient.path,
      },
    });
    for (const p of params_) this.registrar.node.addDependency(p);
    this.registrar.node.addDependency(this.resourceServer);
    this.registrar.fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ["ssm:GetParameter", "ssm:GetParametersByPath"],
      resources: [`arn:${this.partition}:ssm:${this.region}:${this.account}:parameter${cfg.ssmPrefix}`,
        `arn:${this.partition}:ssm:${this.region}:${this.account}:parameter${cfg.ssmPrefix}/*`],
    }));
    this.registrar.fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
      resources: [table.tableArn],
    }));
    this.registrar.fn.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        "cognito-idp:CreateUserPoolClient", "cognito-idp:UpdateUserPoolClient", "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:DescribeUserPoolClient", "cognito-idp:ListUserPoolClients",
        "cognito-idp:CreateManagedLoginBranding", "cognito-idp:DescribeManagedLoginBrandingByClient",
        "cognito-idp:UpdateManagedLoginBranding", "cognito-idp:DeleteManagedLoginBranding",
      ],
      resources: [userPool.userPoolArn],
    }));

    new events.Rule(this, "RegistrarSchedule", {
      schedule: events.Schedule.expression(cfg.cimd.registrarSchedule),
      targets: [new targets.LambdaFunction(this.registrar.fn, { retryAttempts: 0 })],
    });

    // Deploy-time run: re-runs whenever the allow-list or reaction-relevant config changes.
    this.registrarProvider = new cr.Provider(this, "RegistrarProvider", { onEventHandler: this.registrar.fn });
    const configHash = createHash("sha256").update(JSON.stringify({
      allowedClients: cfg.cimd.allowedClients, cimd: cfg.cimd, scope: cfg.cognito.scopeName, testClient: cfg.testClient,
      access: cfg.cognito.accessTokenMinutes, refresh: cfg.cognito.refreshTokenDays,
    })).digest("hex");
    const run = new cdk.CustomResource(this, "RegistrarRun", {
      serviceToken: this.registrarProvider.serviceToken,
      resourceType: "Custom::CimdRegistrarRun",
      properties: { configHash },
    });
    run.node.addDependency(this.resourceServer);
    for (const p of params_) run.node.addDependency(p);

    if (cfg.devFixtures.preRegisteredClient) {
      this.addDevFixture(cfg, userPool, table);
    }

    new cdk.CfnOutput(this, "PublicBaseUrl", { value: urls.publicBaseUrl });
    new cdk.CfnOutput(this, "ResourceUrl", { value: urls.resourceUrl });
    new cdk.CfnOutput(this, "InvokeScope", { value: urls.invokeScope });
  }

  /**
   * Dev fixture: a public app client standing in for a registrar-created shadow client, plus the
   * mapping row the registered-client verifier expects. Removed by setting devFixtures.preRegisteredClient=false.
   */
  private addDevFixture(cfg: Config, userPool: cognito.IUserPool, table: dynamodb.ITable) {
    const client = new cognito.UserPoolClient(this, "DevFixtureClient", {
      userPool,
      userPoolClientName: `${cfg.project.name}-${cfg.project.stage}-dev-fixture`,
      generateSecret: false,
      authFlows: { user: false, userSrp: false, userPassword: false, custom: false },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.resourceServer(this.resourceServer, new cognito.ResourceServerScope({ scopeName: cfg.cognito.scopeName, scopeDescription: "Invoke MCP tools" }))],
        callbackUrls: [`http://localhost:${cfg.devFixtures.callbackPort}/callback`],
      },
      accessTokenValidity: cdk.Duration.minutes(cfg.cognito.accessTokenMinutes),
      refreshTokenValidity: cdk.Duration.days(cfg.cognito.refreshTokenDays),
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
    });
    client.node.addDependency(this.resourceServer);
    new cognito.CfnManagedLoginBranding(this, "DevFixtureBranding", {
      userPoolId: userPool.userPoolId,
      clientId: client.userPoolClientId,
      useCognitoProvidedValues: true,
    });

    const pk = `INDEX#COGNITO#${client.userPoolClientId}`;
    new cr.AwsCustomResource(this, "DevFixtureMapping", {
      onUpdate: {
        service: "DynamoDB",
        action: "putItem",
        parameters: {
          TableName: table.tableName,
          Item: { pk: { S: pk }, cimd_url: { S: "fixture://dev-pre-registered-client" }, enabled: { BOOL: true } },
        },
        physicalResourceId: cr.PhysicalResourceId.of(pk),
      },
      onDelete: {
        service: "DynamoDB",
        action: "deleteItem",
        parameters: { TableName: table.tableName, Key: { pk: { S: pk } } },
      },
      policy: cr.AwsCustomResourcePolicy.fromSdkCalls({ resources: [table.tableArn] }),
      installLatestAwsSdk: false,
    });

    new cdk.CfnOutput(this, "DevFixtureClientId", { value: client.userPoolClientId });
  }
}
