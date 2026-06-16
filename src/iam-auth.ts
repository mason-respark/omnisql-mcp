/**
 * Native AWS IAM database authentication for Aurora connections.
 *
 * The MCP server connects to databases directly (it does not drive DBeaver), so
 * for an Aurora IAM connection it must mint a short-lived RDS IAM auth token from
 * the connection's AWS profile instead of reading a stored password. When the
 * underlying AWS SSO session is expired, token minting raises an AUTH_REQUIRED
 * error so the query path can surface a "log in or skip" prompt rather than
 * crashing. See docs/superpowers/specs/2026-06-16-mcp-aurora-iam-auth-design.md.
 */
import { spawn as nodeSpawn } from 'child_process';
import type { DatabaseConnection } from './types.js';
import { getNestedDriverProps } from './utils.js';

export type IamAuthErrorKind =
  | 'AUTH_REQUIRED'
  | 'PROFILE_NOT_FOUND'
  | 'MISSING_USERNAME'
  | 'REGION_UNKNOWN'
  | 'TOKEN_MINT_FAILED'
  | 'AWS_CLI_NOT_FOUND'
  | 'LOGIN_TIMEOUT'
  | 'LOGIN_FAILED';

export class IamAuthError extends Error {
  readonly kind: IamAuthErrorKind;
  readonly profile?: string;
  readonly connectionName?: string;

  constructor(
    kind: IamAuthErrorKind,
    message: string,
    opts: { profile?: string; connectionName?: string; cause?: unknown } = {}
  ) {
    super(message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = 'IamAuthError';
    this.kind = kind;
    this.profile = opts.profile;
    this.connectionName = opts.connectionName;
  }
}

export type IamEngine = 'postgres' | 'mysql';

export interface IamConnectionParams {
  profile: string;
  region: string;
  host: string;
  port: number;
  database: string;
  username: string;
  sslRootCert?: string;
}

function readString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * A connection's AWS profile — the connector's fingerprint, present in both
 * connection shapes, and the value used to drive `aws sso login`.
 */
export function getAwsProfile(connection: DatabaseConnection): string | undefined {
  return readString(getNestedDriverProps(connection)['awsProfile']);
}

function detectEngine(connection: DatabaseConnection): IamEngine {
  const driver = connection.driver.toLowerCase();
  if (driver.includes('mysql')) return 'mysql';
  if (driver.includes('postgres')) return 'postgres';
  // Bootstrap shape: GUID driver, engine encoded in the jdbc:aws-wrapper url scheme.
  const url = (connection.url || '').toLowerCase();
  if (url.includes('aws-wrapper:mysql')) return 'mysql';
  return 'postgres';
}

/**
 * Identify an Aurora IAM connection by its fingerprint — a non-empty `awsProfile`
 * in the nested driver properties — and resolve the target engine.
 */
export function isAuroraIamConnection(connection: DatabaseConnection): {
  isIam: boolean;
  engine: IamEngine | null;
} {
  if (!getAwsProfile(connection)) return { isIam: false, engine: null };
  return { isIam: true, engine: detectEngine(connection) };
}

/** Extract the AWS region from an RDS endpoint hostname, e.g. `*.us-east-2.rds.amazonaws.com`. */
export function parseRegionFromRdsHostname(host: string): string | null {
  // Region is the label before `.rds.amazonaws.com`; allow multi-segment regions
  // (us-gov-west-1, us-iso-east-1) and the China partition suffix (.com.cn).
  const match = /\.([a-z]{2}-[a-z-]+-\d+)\.rds\.amazonaws\.com(?:\.cn)?$/i.exec(host);
  return match ? match[1] : null;
}

/** Resolve everything needed to mint a token and connect, or throw a typed IamAuthError. */
export function resolveIamConnectionParams(connection: DatabaseConnection): IamConnectionParams {
  const nested = getNestedDriverProps(connection);

  const profile = getAwsProfile(connection);
  if (!profile) {
    throw new IamAuthError(
      'PROFILE_NOT_FOUND',
      'No AWS profile is configured for this connection.',
      {
        connectionName: connection.name,
      }
    );
  }

  const host = connection.host || readString(connection.properties?.host) || '';
  const region = readString(nested['iamRegion']) || parseRegionFromRdsHostname(host) || '';
  if (!region) {
    throw new IamAuthError(
      'REGION_UNKNOWN',
      `Could not determine an AWS region for "${connection.name}": set iamRegion or use an RDS hostname.`,
      { profile, connectionName: connection.name }
    );
  }

  const username = connection.user || readString(connection.properties?.user);
  if (!username) {
    throw new IamAuthError(
      'MISSING_USERNAME',
      `No database username is set for "${connection.name}"; IAM tokens are minted per user.`,
      { profile, connectionName: connection.name }
    );
  }

  const engine = detectEngine(connection);
  let port = connection.port;
  if (!port) {
    const parsed = connection.properties?.port ? parseInt(connection.properties.port, 10) : NaN;
    port = Number.isNaN(parsed) ? (engine === 'mysql' ? 3306 : 5432) : parsed;
  }
  const database =
    connection.database ||
    readString(connection.properties?.database) ||
    (engine === 'mysql' ? '' : 'postgres');
  const sslRootCert =
    readString(nested['sslrootcert']) || readString(connection.properties?.['sslrootcert']);

  return { profile, region, host, port, database, username, sslRootCert };
}

/** IAM auth is on unless explicitly disabled via OMNISQL_IAM_AUTH=false. */
export function isIamAuthEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env.OMNISQL_IAM_AUTH !== 'false';
}

/**
 * Decide whether a Postgres-family connection should authenticate via IAM, and
 * if so return the resolved params (the caller mints the token, so the minter
 * stays a directly-imported export — important for both pooled and single-shot
 * connection paths). Returns null when IAM is disabled, the connection is not an
 * Aurora IAM connection, or a stored password already exists (stored wins).
 * Throws IamAuthError when the connection is IAM but misconfigured.
 */
export function getIamAuth(
  connection: DatabaseConnection,
  env: Record<string, string | undefined> = process.env
): IamConnectionParams | null {
  if (!isIamAuthEnabled(env)) return null;
  if (!isAuroraIamConnection(connection).isIam) return null;
  if (readString(connection.properties?.password)) return null;
  return resolveIamConnectionParams(connection);
}

/** Map an arbitrary AWS SDK / CLI error to an IamAuthErrorKind. */
export function classifyAwsAuthError(error: unknown): IamAuthErrorKind {
  const message = (error instanceof Error ? error.message : String(error)).toLowerCase();
  // Only treat "expired" as a re-auth signal when it refers to an auth artifact —
  // otherwise an unrelated "certificate has expired" would prompt a pointless login.
  const expiredAuth =
    /expired/.test(message) && /(token|session|credential|sso|profile)/.test(message);
  if (
    expiredAuth ||
    /reauthenticate/.test(message) ||
    /sso session/.test(message) ||
    /sso login/.test(message)
  ) {
    return 'AUTH_REQUIRED';
  }
  if (/profile.*(could not be found|not found|does not exist)/.test(message)) {
    return 'PROFILE_NOT_FOUND';
  }
  return 'TOKEN_MINT_FAILED';
}

/** Test seam: mint the token directly, bypassing the AWS SDK. */
export type MintTokenOverride = (params: IamConnectionParams) => Promise<string>;

async function defaultMintToken(params: IamConnectionParams): Promise<string> {
  const { fromIni } = await import('@aws-sdk/credential-providers');
  const { Signer } = await import('@aws-sdk/rds-signer');
  const signer = new Signer({
    hostname: params.host,
    port: params.port,
    username: params.username,
    region: params.region,
    credentials: fromIni({ profile: params.profile }),
  });
  return signer.getAuthToken();
}

/**
 * Mint a fresh RDS IAM auth token (used as the DB password). Throws an
 * IamAuthError; an expired SSO session classifies as AUTH_REQUIRED so callers
 * can prompt for `aws sso login`.
 */
export async function mintIamAuthToken(
  params: IamConnectionParams,
  mint: MintTokenOverride = defaultMintToken
): Promise<string> {
  try {
    return await mint(params);
  } catch (error) {
    if (error instanceof IamAuthError) throw error;
    const kind = classifyAwsAuthError(error);
    const message =
      kind === 'AUTH_REQUIRED'
        ? `AWS SSO session for profile "${params.profile}" has expired. Run aws sso login --profile ${params.profile}.`
        : `Failed to mint an IAM auth token for profile "${params.profile}": ${
            error instanceof Error ? error.message : String(error)
          }`;
    throw new IamAuthError(kind, message, { profile: params.profile, cause: error });
  }
}

export interface AuthRequiredInfo {
  status: 'auth_required';
  profile?: string;
  connection?: string;
  message: string;
  action: string;
}

/**
 * Describe an AUTH_REQUIRED error as structured guidance the model can act on:
 * ask the user to log in (via the aws_sso_login tool) or skip, then retry.
 */
export function describeAuthRequired(error: IamAuthError): AuthRequiredInfo {
  const profile = error.profile;
  const target = profile ? `profile "${profile}"` : 'the connection';
  return {
    status: 'auth_required',
    profile,
    connection: error.connectionName,
    message: error.message,
    action:
      `The AWS SSO session for ${target} has expired. Ask the user whether to log in or skip. ` +
      `To log in, call the aws_sso_login tool (with the connectionId or profile), then retry this request.`,
  };
}

export type SpawnLike = typeof nodeSpawn;

export interface SsoLoginOptions {
  timeoutMs?: number;
  env?: Record<string, string | undefined>;
  deps?: { spawn: SpawnLike };
}

export interface SsoLoginResult {
  profile: string;
  output: string;
}

/** Resolve the SSO-login timeout (ms) from OMNISQL_SSO_LOGIN_TIMEOUT (seconds), default 180s. */
export function resolveSsoLoginTimeoutMs(
  env: Record<string, string | undefined> = process.env
): number {
  const configured = Number(env.OMNISQL_SSO_LOGIN_TIMEOUT);
  return Number.isFinite(configured) && configured > 0 ? configured * 1000 : 180_000;
}

/**
 * Run `aws sso login --profile <profile>`. The AWS CLI opens a browser; this
 * blocks until it exits (or times out). Rejects with a typed IamAuthError.
 */
export function runSsoLogin(profile: string, opts: SsoLoginOptions = {}): Promise<SsoLoginResult> {
  const spawnFn = opts.deps?.spawn ?? nodeSpawn;
  const env = opts.env ?? process.env;
  const timeoutMs = opts.timeoutMs ?? resolveSsoLoginTimeoutMs(env);

  return new Promise<SsoLoginResult>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    const child = spawnFn('aws', ['sso', 'login', '--profile', profile], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let output = '';
    child.stdout?.on('data', (d: Buffer) => (output += d.toString()));
    child.stderr?.on('data', (d: Buffer) => (output += d.toString()));

    const timer = setTimeout(() => {
      child.kill();
      finish(() =>
        reject(
          new IamAuthError(
            'LOGIN_TIMEOUT',
            `aws sso login for profile "${profile}" timed out after ${timeoutMs}ms.`,
            { profile }
          )
        )
      );
    }, timeoutMs);

    child.on('error', (err: NodeJS.ErrnoException) => {
      const kind = err.code === 'ENOENT' ? 'AWS_CLI_NOT_FOUND' : 'LOGIN_FAILED';
      const message =
        kind === 'AWS_CLI_NOT_FOUND'
          ? 'The AWS CLI ("aws") was not found on PATH; install it to run aws sso login.'
          : `Failed to run aws sso login for profile "${profile}": ${err.message}`;
      finish(() => reject(new IamAuthError(kind, message, { profile, cause: err })));
    });

    child.on('close', (code: number | null) => {
      finish(() => {
        if (code === 0) {
          resolve({ profile, output });
        } else {
          reject(
            new IamAuthError(
              'LOGIN_FAILED',
              `aws sso login for profile "${profile}" exited with code ${code}: ${output.trim()}`,
              { profile }
            )
          );
        }
      });
    });
  });
}
