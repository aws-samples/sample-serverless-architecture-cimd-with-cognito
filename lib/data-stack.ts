import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";
import type { Config } from "../config";

export interface DataStackProps extends cdk.StackProps {
  cfg: Config;
}

/** Single-table store: CLIENT#<cimd_url>, INDEX#COGNITO#<client_id>, LOCK#registrar. Written by the registrar only. */
export class DataStack extends cdk.Stack {
  readonly table: dynamodb.Table;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);
    const { cfg } = props;
    const isProd = cfg.project.stage === "prod";

    this.table = new dynamodb.Table(this, "Table", {
      tableName: `${cfg.project.name}-${cfg.project.stage}-cimd`,
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      timeToLiveAttribute: "ttl",
      removalPolicy: isProd ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      deletionProtection: isProd,
    });

    new cdk.CfnOutput(this, "TableName", { value: this.table.tableName });
  }
}
