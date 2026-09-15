#!/usr/bin/env node
/**
 * CDK app entry point. Validates config.ts, then instantiates the four stacks in dependency order
 * (userpool → data → api → registration), applies the optional permissions boundary to every role, and runs cdk-nag
 * suppressions. Public URLs are never passed to Lambdas here; RegistrationStack writes them to SSM.
 */
import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { config } from "../config";
import { ApiStack } from "../lib/api-stack";
import { DataStack } from "../lib/data-stack";
import { RegistrationStack } from "../lib/registration-stack";
import { UserPoolStack } from "../lib/user-pool-stack";
import { stackName, validateConfig } from "../lib/derive";
import { applyNagSuppressions } from "../lib/nag-suppressions";

validateConfig(config);

const app = new cdk.App();
const env = { account: process.env.CDK_DEFAULT_ACCOUNT, region: config.project.region };

const userPool = new UserPoolStack(app, stackName(config, "userpool"), { cfg: config, env });
const data = new DataStack(app, stackName(config, "data"), { cfg: config, env });
const api = new ApiStack(app, stackName(config, "api"), {
  cfg: config, env, userPool: userPool.userPool, loginBaseUrl: userPool.domain.baseUrl(), table: data.table,
});

if (config.edge.enabled) {
  // Reserved: EdgeSecurityStack (us-east-1 WAF) and EdgeStack (CloudFront); RegistrationStack would take publicHost from EdgeStack.
  throw new Error("edge.enabled is not implemented in this release. Set edge.enabled=false.");
}

const registration = new RegistrationStack(app, stackName(config, "registration"), {
  cfg: config, env, userPool: userPool.userPool, table: data.table, originBaseUrl: api.originBaseUrl,
});
registration.addStackDependency(api);

// Some accounts require every IAM role to carry a permissions boundary.
if (config.iam.permissionsBoundaryArn) {
  for (const stack of [userPool, data, api, registration]) {
    iam.PermissionsBoundary.of(stack).apply(
      iam.ManagedPolicy.fromManagedPolicyArn(stack, "PermissionsBoundary", config.iam.permissionsBoundaryArn),
    );
  }
}

applyNagSuppressions({ userPool, api, registration, others: [data] });

cdk.Tags.of(app).add("project", config.project.name);
cdk.Tags.of(app).add("stage", config.project.stage);
