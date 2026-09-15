import * as cdk from "aws-cdk-lib";
import * as cognito from "aws-cdk-lib/aws-cognito";
import { Construct } from "constructs";
import type { Config } from "../config";
import { loginDomainPrefix } from "./derive";

export interface UserPoolStackProps extends cdk.StackProps {
  cfg: Config;
}

/** Cognito user pool: the token issuer. Essentials plan, Managed Login v2, groups, optional demo users. */
export class UserPoolStack extends cdk.Stack {
  readonly userPool: cognito.UserPool;
  readonly domain: cognito.UserPoolDomain;

  constructor(scope: Construct, id: string, props: UserPoolStackProps) {
    super(scope, id, props);
    const { cfg } = props;
    const isProd = cfg.project.stage === "prod";

    this.userPool = new cognito.UserPool(this, "UserPool", {
      userPoolName: `${cfg.project.name}-${cfg.project.stage}`,
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      selfSignUpEnabled: false,
      signInAliases: { username: true, email: true },
      autoVerify: { email: true },
      passwordPolicy: { minLength: 12, requireLowercase: true, requireUppercase: true, requireDigits: true, requireSymbols: true },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      mfa: cognito.Mfa.OFF, // MFA is deliberately not showcased (see docs)
      removalPolicy: isProd ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      deletionProtection: isProd,
    });

    this.domain = this.userPool.addDomain("Domain", {
      managedLoginVersion: cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
      ...(cfg.cognito.customLoginDomain
        ? {
            customDomain: {
              domainName: cfg.cognito.customLoginDomain,
              certificate: cdk.aws_certificatemanager.Certificate.fromCertificateArn(this, "LoginCert", cfg.cognito.loginCertificateArn),
            },
          }
        : { cognitoDomain: { domainPrefix: loginDomainPrefix(cfg, this.account) } }),
    });

    for (const groupName of cfg.cognito.groups) {
      new cognito.CfnUserPoolGroup(this, `Group-${groupName}`, { userPoolId: this.userPool.userPoolId, groupName });
    }

    if (cfg.cognito.createDemoUsers) {
      for (const u of cfg.cognito.demoUsers) {
        const user = new cognito.CfnUserPoolUser(this, `DemoUser-${u.username}`, {
          userPoolId: this.userPool.userPoolId,
          username: u.username,
          messageAction: "SUPPRESS", // no email; password is set at test time with AdminSetUserPassword, never stored
          userAttributes: [
            { name: "email", value: u.email },
            { name: "email_verified", value: "true" },
          ],
        });
        const attach = new cognito.CfnUserPoolUserToGroupAttachment(this, `DemoUserGroup-${u.username}`, {
          userPoolId: this.userPool.userPoolId,
          username: u.username,
          groupName: u.group,
        });
        attach.addResourceDependency(user);
        attach.node.addDependency(this.node.findChild(`Group-${u.group}`));
      }
    }

    new cdk.CfnOutput(this, "UserPoolId", { value: this.userPool.userPoolId });
    new cdk.CfnOutput(this, "LoginBaseUrl", { value: this.domain.baseUrl() });
  }
}
