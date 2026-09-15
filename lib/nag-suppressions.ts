import * as cdk from "aws-cdk-lib";
import * as apigwv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { NagSuppressions } from "cdk-nag";
import type { ApiStack } from "./api-stack";
import type { RegistrationStack } from "./registration-stack";
import type { UserPoolStack } from "./user-pool-stack";

/**
 * cdk-nag AwsSolutions suppressions, resource-scoped with `appliesTo` so that new permissions or
 * routes added later are NOT silently covered. Every entry states why.
 */
export function applyNagSuppressions(opts: { userPool: UserPoolStack; api: ApiStack; registration: RegistrationStack; others: cdk.Stack[] }): void {
  const { userPool, api, registration } = opts;

  // Cognito user-pool posture. Each reason is self-contained on purpose: these are the deliberate scope choices
  // of a sample about CIMD translation, and README §12 "Out of scope" is the published statement of them.
  NagSuppressions.addResourceSuppressions(userPool.userPool, [
    { id: "AwsSolutions-COG2", reason: "MFA is out of scope for this sample (README §12). Nothing in the CIMD translation layer depends on the authentication factors Cognito uses, so enabling MFA is a user-pool setting a deployer can turn on without touching this code. A production deployment should." },
    { id: "AwsSolutions-COG3", reason: "Advanced security mode (threat protection) requires the Cognito Plus feature plan; this sample runs on Essentials to keep the cost of a reference deployment low. Enable Plus and threat protection for production." },
    { id: "AwsSolutions-COG8", reason: "Essentials feature plan is sufficient for what this sample demonstrates: it mints no tokens of its own and adds no authentication surface beyond Cognito's own hosted Managed Login, so Plus-tier threat protection is not required to exercise the CIMD flow." },
  ]);

  // Lambda functions: managed logging policy and pinned runtime
  for (const fn of [api.mcpServer.fn, api.cimdProxy.fn]) {
    suppressLambdaBaseline(fn, api);
  }

  // Registrar Lambda and the CDK Provider framework function that invokes it on deploy
  suppressLambdaBaseline(registration.registrar.fn, registration);
  NagSuppressions.addResourceSuppressions(registration.registrarProvider, [
    { id: "AwsSolutions-IAM4", reason: "CDK custom-resource Provider framework function uses AWSLambdaBasicExecutionRole.",
      appliesTo: ["Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"] },
    { id: "AwsSolutions-IAM5", reason: "CDK Provider framework needs lambda:InvokeFunction on the registrar function and its versions (framework-generated policy).",
      appliesTo: [{ regex: "/^Resource::<.*Registrar.*Fn.*\\.Arn>:\\*$/g" }] },
    { id: "AwsSolutions-L1", reason: "Provider framework runtime is chosen by aws-cdk-lib, not by this project." },
  ], true);

  // Every route is intentionally unauthenticated at the API Gateway layer:
  // OAuth metadata routes MUST be public per RFC 8414/9728; /mcp is authenticated in-process by FastMCP
  // (JWTVerifier: Cognito issuer, audience = resourceUrl, required scope, registered client).
  for (const child of api.httpApi.node.findAll()) {
    if (child instanceof apigwv2.HttpRoute) {
      const key = (child.node.defaultChild as apigwv2.CfnRoute).routeKey;
      const reason = String(key).includes("/mcp")
        ? "Authorization for /mcp is enforced in-process by FastMCP JWTVerifier (Cognito issuer, audience, scope, registered client)."
        : "OAuth discovery and authorization endpoints must be reachable without a token per RFC 8414 / RFC 9728 / OAuth 2.1.";
      NagSuppressions.addResourceSuppressions(child, [{ id: "AwsSolutions-APIG4", reason }]);
    }
  }
}

/** Lambda baseline: AWSLambdaBasicExecutionRole and the SSM prefix wildcard, and nothing else. */
export function suppressLambdaBaseline(fn: lambda.Function, stack: cdk.Stack): void {
  NagSuppressions.addResourceSuppressions(fn, [
    { id: "AwsSolutions-L1", reason: "Python 3.12 is pinned deliberately (runtime.pythonVersion) for FastMCP compatibility and uv cross-platform bundling." },
  ]);
  const role = fn.role!;
  NagSuppressions.addResourceSuppressions(role, [
    {
      id: "AwsSolutions-IAM4",
      reason: "AWSLambdaBasicExecutionRole is the standard managed policy for CloudWatch logging; log groups are created explicitly with retention.",
      appliesTo: ["Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    },
  ], true);
  NagSuppressions.addResourceSuppressions(role, [
    {
      id: "AwsSolutions-IAM5",
      reason: "SSM GetParametersByPath requires the prefix ARN and prefix/*; both are pinned to this deployment's ssmPrefix.",
      appliesTo: [{ regex: "/^Resource::arn:<AWS::Partition>:ssm:.*:parameter/[^*]+/\\*$/g" }],
    },
  ], true);
  void stack;
}
