/**
 * PythonLambda construct: a Python 3.12 arm64 function whose dependencies are installed from uv.lock for the Lambda
 * platform without Docker, with lambdas/shared/ and the function directory copied in. See the class comment below.
 */
import * as cdk from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import type { Config } from "../../config";

export interface PythonLambdaProps {
  cfg: Config;
  /** directory name under lambdas/, also the uv dependency group name (with '_' → '-') */
  name: string;
  handler: string;
  environment: Record<string, string>;
  memoryMb?: number;
  timeoutSeconds?: number;
  functionName?: string;
}

/**
 * Python 3.12 arm64 Lambda bundled WITHOUT Docker: dependencies are resolved from uv.lock for the
 * function's dependency group and installed for the Lambda platform, then shared/ and the function
 * source are copied in. URLs are never passed as environment variables: they are written to SSM by the last stack
 * and read at runtime, which avoids the API -> Lambda -> API dependency cycle.
 */
export class PythonLambda extends Construct {
  readonly fn: lambda.Function;
  readonly logGroup: logs.LogGroup;

  constructor(scope: Construct, id: string, props: PythonLambdaProps) {
    super(scope, id);
    const { cfg, name } = props;
    const repoRoot = path.resolve(__dirname, "..", "..");
    const group = name.replace(/_/g, "-");
    const runtime = cfg.runtime.pythonVersion === "3.12" ? lambda.Runtime.PYTHON_3_12 : lambda.Runtime.PYTHON_3_12;

    this.logGroup = new logs.LogGroup(this, "LogGroup", {
      retention: retentionFromDays(cfg.runtime.logRetentionDays),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.fn = new lambda.Function(this, "Fn", {
      runtime,
      architecture: lambda.Architecture.ARM_64,
      handler: props.handler,
      functionName: props.functionName,
      memorySize: props.memoryMb ?? cfg.runtime.lambdaMemoryMb,
      timeout: cdk.Duration.seconds(props.timeoutSeconds ?? cfg.runtime.lambdaTimeoutSeconds),
      logGroup: this.logGroup,
      environment: { LOG_LEVEL: cfg.runtime.logLevel, ...props.environment },
      code: lambda.Code.fromAsset(repoRoot, {
        assetHashType: cdk.AssetHashType.CUSTOM,
        assetHash: sourceHash(repoRoot, name),
        bundling: {
          image: runtime.bundlingImage,
          local: { tryBundle: (outputDir: string) => bundleLocally(repoRoot, name, group, cfg.runtime.pythonVersion, outputDir) },
        },
      }),
    });
  }
}

function bundleLocally(repoRoot: string, name: string, group: string, pyVersion: string, outputDir: string): boolean {
  const req = path.join(outputDir, "requirements.txt");
  const run = (args: string[]) => execFileSync("uv", args, { cwd: repoRoot, stdio: ["ignore", "pipe", "inherit"] });
  run(["export", "--frozen", "--no-dev", "--no-hashes", "--no-emit-project", "--only-group", group, "--output-file", req]);
  const reqText = fs.readFileSync(req, "utf8").split("\n").filter((l) => l && !l.startsWith("#")).join("\n");
  if (reqText.trim().length > 0) {
    run(["pip", "install", "--quiet", "--requirement", req, "--python-platform", "aarch64-manylinux2014",
      "--python-version", pyVersion, "--only-binary", ":all:", "--target", outputDir]);
  }
  fs.rmSync(req, { force: true });
  copyTree(path.join(repoRoot, "lambdas", "shared"), path.join(outputDir, "shared"));
  copyTree(path.join(repoRoot, "lambdas", name), outputDir);
  return true;
}

function copyTree(src: string, dst: string) {
  fs.mkdirSync(dst, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name === "__pycache__" || entry.name.endsWith(".pyc") || entry.name.startsWith(".")) continue;
    const s = path.join(src, entry.name);
    const d = path.join(dst, entry.name);
    if (entry.isDirectory()) copyTree(s, d);
    else fs.copyFileSync(s, d);
  }
}

/**
 * Hash of the lock file, pyproject, this bundler's own source, and the function's and shared sources
 * (paths relative to the repo root so the hash is machine-independent). Unchanged inputs do not redeploy;
 * a change to the bundling logic does.
 */
function sourceHash(repoRoot: string, name: string): string {
  const { createHash } = require("crypto") as typeof import("crypto");
  const h = createHash("sha256");
  h.update("python-lambda-bundler-v1");
  for (const f of ["uv.lock", "pyproject.toml", path.relative(repoRoot, __filename)]) {
    h.update(f).update(fs.readFileSync(path.join(repoRoot, f)));
  }
  for (const dir of [path.join(repoRoot, "lambdas", "shared"), path.join(repoRoot, "lambdas", name)]) {
    for (const f of walk(dir)) h.update(path.relative(repoRoot, f)).update(fs.readFileSync(f));
  }
  return h.digest("hex");
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name === "__pycache__" || entry.name.endsWith(".pyc")) continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

function retentionFromDays(days: number): logs.RetentionDays {
  const allowed = [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653];
  const pick = allowed.find((d) => d >= days) ?? 3653;
  return pick as unknown as logs.RetentionDays;
}
