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
import type { DatabaseConnection } from './types.js';

export type IamAuthErrorKind =
  | 'AUTH_REQUIRED'
  | 'PROFILE_NOT_FOUND'
  | 'MISSING_USERNAME'
  | 'REGION_UNKNOWN'
  | 'TOKEN_MINT_FAILED'
  | 'AWS_CLI_NOT_FOUND'
  | 'LOGIN_TIMEOUT';

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

/**
 * The driver-level properties DBeaver stores under the nested `properties` key
 * of a connection's configuration. The MCP's config-parser spreads the parsed
 * config into `connection.properties`, so this nested map lands at
 * `connection.properties.properties`.
 */
function nestedProps(connection: DatabaseConnection): Record<string, unknown> {
  const nested = connection.properties?.['properties'];
  return nested && typeof nested === 'object' ? (nested as Record<string, unknown>) : {};
}

function readString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/** The AWS profile is the connector's fingerprint, present in both connection shapes. */
function awsProfileOf(connection: DatabaseConnection): string | undefined {
  return readString(nestedProps(connection)['awsProfile']);
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
  if (!awsProfileOf(connection)) return { isIam: false, engine: null };
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
  const nested = nestedProps(connection);

  const profile = awsProfileOf(connection);
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

export interface RdsSignerOptions {
  hostname: string;
  port: number;
  username: string;
  region: string;
  credentials: unknown;
}

export interface IamAuthDeps {
  loadCredentials: (profile: string) => unknown | Promise<unknown>;
  createSigner: (
    opts: RdsSignerOptions
  ) => { getAuthToken: () => Promise<string> } | Promise<{ getAuthToken: () => Promise<string> }>;
}

function defaultIamAuthDeps(): IamAuthDeps {
  return {
    loadCredentials: async (profile) => {
      const { fromIni } = await import('@aws-sdk/credential-providers');
      return fromIni({ profile });
    },
    createSigner: async (opts) => {
      const { Signer } = await import('@aws-sdk/rds-signer');
      return new Signer(opts as unknown as ConstructorParameters<typeof Signer>[0]);
    },
  };
}

/**
 * Mint a fresh RDS IAM auth token (used as the DB password). Throws an
 * IamAuthError; an expired SSO session classifies as AUTH_REQUIRED so callers
 * can prompt for `aws sso login`.
 */
export async function mintIamAuthToken(
  params: IamConnectionParams,
  deps: IamAuthDeps = defaultIamAuthDeps()
): Promise<string> {
  try {
    const credentials = await deps.loadCredentials(params.profile);
    const signer = await deps.createSigner({
      hostname: params.host,
      port: params.port,
      username: params.username,
      region: params.region,
      credentials,
    });
    return await signer.getAuthToken();
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
