import { describe, it, expect, vi } from 'vitest';
import { EventEmitter } from 'events';
import {
  isAuroraIamConnection,
  parseRegionFromRdsHostname,
  resolveIamConnectionParams,
  classifyAwsAuthError,
  mintIamAuthToken,
  isIamAuthEnabled,
  getIamAuth,
  getAwsProfile,
  runSsoLogin,
  resolveSsoLoginTimeoutMs,
  describeAuthRequired,
  IamAuthError,
} from './iam-auth.js';
import type { DatabaseConnection } from './types.js';

/** A fake child process that lets a test drive stdout/stderr/close/error events. */
function fakeChild() {
  const child = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: ReturnType<typeof vi.fn>;
  };
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn();
  return child;
}

// A plugin-created Aurora IAM connection: no url / no wrapperPlugins persisted,
// driver = aurora-postgresql, awsProfile lives in the nested `properties` map.
function pluginConn(overrides: Partial<DatabaseConnection> = {}): DatabaseConnection {
  return {
    id: 'aurora-pg-1',
    name: 'aurora_pg_prod',
    driver: 'aurora-postgresql',
    url: '',
    host: 'infra-rdscluster-x.cluster-abc.us-east-2.rds.amazonaws.com',
    port: 5432,
    database: 'postgres',
    user: 'app_user',
    properties: {
      properties: {
        awsProfile: 'example-sso-profile',
        iamRegion: 'us-east-2',
        sslrootcert: '/home/me/.aws/rds-global-bundle.pem',
      },
    } as unknown as Record<string, string>,
    ...overrides,
  };
}

// A bootstrap-script-created connection: GUID driver, url = jdbc:aws-wrapper:…,
// wrapperPlugins + awsProfile in nested props.
function bootstrapConn(overrides: Partial<DatabaseConnection> = {}): DatabaseConnection {
  return {
    id: 'guid-1',
    name: 'aurora-bootstrap',
    driver: '27DA594F-326B-45B3-E2BC-637BBCA4777D',
    url: 'jdbc:aws-wrapper:postgresql://infra-rdscluster-x.cluster-abc.us-east-2.rds.amazonaws.com:5432/postgres',
    host: 'infra-rdscluster-x.cluster-abc.us-east-2.rds.amazonaws.com',
    port: 5432,
    database: 'postgres',
    user: 'app_user',
    properties: {
      properties: {
        wrapperPlugins: 'iam',
        awsProfile: 'example-sso-profile',
        iamRegion: 'us-east-2',
      },
    } as unknown as Record<string, string>,
    ...overrides,
  };
}

function stockPgConn(): DatabaseConnection {
  return {
    id: 'pg-1',
    name: 'plain-pg',
    driver: 'postgres-jdbc',
    url: 'jdbc:postgresql://db.example.com:5432/app',
    host: 'db.example.com',
    port: 5432,
    database: 'app',
    user: 'app',
    properties: { password: 'hunter2', sslmode: 'require' },
  };
}

describe('isAuroraIamConnection', () => {
  it('detects a plugin-created Aurora IAM connection via nested awsProfile', () => {
    expect(isAuroraIamConnection(pluginConn())).toEqual({ isIam: true, engine: 'postgres' });
  });

  it('detects a bootstrap-created connection via nested awsProfile', () => {
    expect(isAuroraIamConnection(bootstrapConn())).toEqual({ isIam: true, engine: 'postgres' });
  });

  it('derives the mysql engine from an aurora-mysql driver', () => {
    const conn = pluginConn({ driver: 'aurora-mysql' });
    expect(isAuroraIamConnection(conn)).toEqual({ isIam: true, engine: 'mysql' });
  });

  it('derives the engine from the jdbc:aws-wrapper url scheme when the driver is a GUID', () => {
    const conn = bootstrapConn({
      url: 'jdbc:aws-wrapper:mysql://host.us-east-2.rds.amazonaws.com:3306/app',
    });
    expect(isAuroraIamConnection(conn)).toEqual({ isIam: true, engine: 'mysql' });
  });

  it('returns isIam=false for a stock Postgres connection (no awsProfile)', () => {
    expect(isAuroraIamConnection(stockPgConn())).toEqual({ isIam: false, engine: null });
  });

  it('treats a blank awsProfile as not-IAM', () => {
    const conn = pluginConn();
    (conn.properties as any).properties.awsProfile = '   ';
    expect(isAuroraIamConnection(conn).isIam).toBe(false);
  });
});

describe('parseRegionFromRdsHostname', () => {
  it('extracts the region from a cluster endpoint', () => {
    expect(
      parseRegionFromRdsHostname('infra-rdscluster-x.cluster-abc.us-east-2.rds.amazonaws.com')
    ).toBe('us-east-2');
  });

  it('extracts the region from a plain instance endpoint', () => {
    expect(parseRegionFromRdsHostname('mydb.abc123.eu-west-1.rds.amazonaws.com')).toBe('eu-west-1');
  });

  it('extracts a gov-cloud region', () => {
    expect(parseRegionFromRdsHostname('mydb.abc.us-gov-west-1.rds.amazonaws.com')).toBe(
      'us-gov-west-1'
    );
  });

  it('extracts a China-partition region (.com.cn endpoint)', () => {
    expect(parseRegionFromRdsHostname('mydb.abc.cn-north-1.rds.amazonaws.com.cn')).toBe(
      'cn-north-1'
    );
  });

  it('extracts a multi-segment region label', () => {
    expect(parseRegionFromRdsHostname('mydb.abc.us-iso-east-1.rds.amazonaws.com')).toBe(
      'us-iso-east-1'
    );
  });

  it('returns null for a non-RDS hostname', () => {
    expect(parseRegionFromRdsHostname('localhost')).toBeNull();
    expect(parseRegionFromRdsHostname('db.internal.corp')).toBeNull();
  });
});

describe('resolveIamConnectionParams', () => {
  it('resolves all params from a plugin connection', () => {
    const params = resolveIamConnectionParams(pluginConn());
    expect(params).toEqual({
      profile: 'example-sso-profile',
      region: 'us-east-2',
      host: 'infra-rdscluster-x.cluster-abc.us-east-2.rds.amazonaws.com',
      port: 5432,
      database: 'postgres',
      username: 'app_user',
      sslRootCert: '/home/me/.aws/rds-global-bundle.pem',
    });
  });

  it('falls back to the region parsed from the hostname when iamRegion is absent', () => {
    const conn = pluginConn();
    delete (conn.properties as any).properties.iamRegion;
    expect(resolveIamConnectionParams(conn).region).toBe('us-east-2');
  });

  it('throws PROFILE_NOT_FOUND when awsProfile is missing', () => {
    const conn = pluginConn();
    delete (conn.properties as any).properties.awsProfile;
    expect(() => resolveIamConnectionParams(conn)).toThrowError(
      expect.objectContaining({ kind: 'PROFILE_NOT_FOUND' })
    );
  });

  it('throws MISSING_USERNAME when no DB user is known', () => {
    const conn = pluginConn({ user: undefined });
    delete (conn.properties as any).user;
    expect(() => resolveIamConnectionParams(conn)).toThrowError(
      expect.objectContaining({ kind: 'MISSING_USERNAME' })
    );
  });

  it('uses MySQL defaults (port 3306) for an aurora-mysql connection without an explicit port', () => {
    const conn = pluginConn({ driver: 'aurora-mysql', port: undefined });
    const params = resolveIamConnectionParams(conn);
    expect(params.port).toBe(3306);
  });

  it('does not force the postgres database name for a MySQL connection', () => {
    const conn = pluginConn({ driver: 'aurora-mysql', port: undefined, database: undefined });
    expect(resolveIamConnectionParams(conn).database).toBe('');
  });

  it('falls back to the default port when properties.port is non-numeric', () => {
    const conn = pluginConn({ port: undefined });
    (conn.properties as any).port = 'not-a-number';
    expect(resolveIamConnectionParams(conn).port).toBe(5432);
  });

  it('throws REGION_UNKNOWN when region is neither configured nor derivable', () => {
    const conn = pluginConn({ host: 'db.internal.corp' });
    delete (conn.properties as any).properties.iamRegion;
    expect(() => resolveIamConnectionParams(conn)).toThrowError(
      expect.objectContaining({ kind: 'REGION_UNKNOWN' })
    );
  });
});

describe('classifyAwsAuthError', () => {
  it('classifies an expired SSO session as AUTH_REQUIRED', () => {
    expect(
      classifyAwsAuthError(
        new Error(
          'The SSO session associated with this profile has expired or is otherwise invalid. To refresh this SSO session run aws sso login with the corresponding profile.'
        )
      )
    ).toBe('AUTH_REQUIRED');
  });

  it('classifies an expired token as AUTH_REQUIRED', () => {
    expect(classifyAwsAuthError(new Error('Token is expired'))).toBe('AUTH_REQUIRED');
  });

  it('classifies a reauthenticate hint as AUTH_REQUIRED', () => {
    expect(classifyAwsAuthError(new Error('Please reauthenticate by running aws sso login'))).toBe(
      'AUTH_REQUIRED'
    );
  });

  it('classifies a missing profile as PROFILE_NOT_FOUND', () => {
    expect(classifyAwsAuthError(new Error("Profile `example-sso-profile' could not be found"))).toBe(
      'PROFILE_NOT_FOUND'
    );
  });

  it('classifies an unknown error as TOKEN_MINT_FAILED', () => {
    expect(classifyAwsAuthError(new Error('connect ETIMEDOUT'))).toBe('TOKEN_MINT_FAILED');
  });
});

describe('getAwsProfile', () => {
  it('returns the profile for an IAM connection', () => {
    expect(getAwsProfile(pluginConn())).toBe('example-sso-profile');
  });

  it('returns undefined for a stock connection', () => {
    expect(getAwsProfile(stockPgConn())).toBeUndefined();
  });
});

describe('describeAuthRequired', () => {
  it('summarizes an AUTH_REQUIRED error for the model to act on', () => {
    const info = describeAuthRequired(
      new IamAuthError('AUTH_REQUIRED', 'SSO expired', {
        profile: 'example-sso-profile',
        connectionName: 'aurora_pg_prod',
      })
    );
    expect(info.status).toBe('auth_required');
    expect(info.profile).toBe('example-sso-profile');
    expect(info.connection).toBe('aurora_pg_prod');
    expect(info.action).toContain('aws_sso_login');
  });
});

describe('resolveSsoLoginTimeoutMs', () => {
  it('defaults to 180s when unset', () => {
    expect(resolveSsoLoginTimeoutMs({})).toBe(180_000);
  });

  it('uses a configured number of seconds', () => {
    expect(resolveSsoLoginTimeoutMs({ OMNISQL_SSO_LOGIN_TIMEOUT: '30' })).toBe(30_000);
  });

  it('falls back to the default for a non-numeric or non-positive value', () => {
    expect(resolveSsoLoginTimeoutMs({ OMNISQL_SSO_LOGIN_TIMEOUT: '180s' })).toBe(180_000);
    expect(resolveSsoLoginTimeoutMs({ OMNISQL_SSO_LOGIN_TIMEOUT: '0' })).toBe(180_000);
  });
});

describe('runSsoLogin', () => {
  it('resolves with captured output when aws sso login exits 0', async () => {
    const child = fakeChild();
    const spawn = vi.fn(() => child) as any;

    const p = runSsoLogin('example-sso-profile', { deps: { spawn } });
    child.stdout.emit('data', Buffer.from('Attempting to open the SSO authorization page...\n'));
    child.emit('close', 0);

    await expect(p).resolves.toMatchObject({ output: expect.stringContaining('authorization') });
    expect(spawn).toHaveBeenCalledWith(
      'aws',
      ['sso', 'login', '--profile', 'example-sso-profile'],
      expect.anything()
    );
  });

  it('rejects with AWS_CLI_NOT_FOUND when aws is not installed (ENOENT)', async () => {
    const child = fakeChild();
    const spawn = vi.fn(() => child) as any;

    const p = runSsoLogin('example-sso-profile', { deps: { spawn } });
    const enoent = Object.assign(new Error('spawn aws ENOENT'), { code: 'ENOENT' });
    child.emit('error', enoent);

    await expect(p).rejects.toMatchObject({ kind: 'AWS_CLI_NOT_FOUND' });
  });

  it('rejects with LOGIN_FAILED on a non-zero exit', async () => {
    const child = fakeChild();
    const spawn = vi.fn(() => child) as any;

    const p = runSsoLogin('example-sso-profile', { deps: { spawn } });
    child.stderr.emit('data', Buffer.from('could not reach SSO endpoint'));
    child.emit('close', 1);

    await expect(p).rejects.toMatchObject({ kind: 'LOGIN_FAILED' });
  });

  it('rejects with LOGIN_TIMEOUT and kills the process when it overruns', async () => {
    const child = fakeChild();
    const spawn = vi.fn(() => child) as any;

    const p = runSsoLogin('example-sso-profile', { timeoutMs: 5, deps: { spawn } });

    await expect(p).rejects.toMatchObject({ kind: 'LOGIN_TIMEOUT' });
    expect(child.kill).toHaveBeenCalled();
  });
});

describe('isIamAuthEnabled', () => {
  it('defaults to enabled', () => {
    expect(isIamAuthEnabled({})).toBe(true);
  });

  it('is disabled only by an explicit "false"', () => {
    expect(isIamAuthEnabled({ OMNISQL_IAM_AUTH: 'false' })).toBe(false);
    expect(isIamAuthEnabled({ OMNISQL_IAM_AUTH: 'true' })).toBe(true);
    expect(isIamAuthEnabled({ OMNISQL_IAM_AUTH: '' })).toBe(true);
  });
});

describe('getIamAuth', () => {
  it('returns null for a stock Postgres connection', () => {
    expect(getIamAuth(stockPgConn(), {})).toBeNull();
  });

  it('returns resolved params for an IAM connection with no stored password', () => {
    expect(getIamAuth(pluginConn(), {})).toMatchObject({
      profile: 'example-sso-profile',
      region: 'us-east-2',
    });
  });

  it('returns null when a stored password is present (stored password wins)', () => {
    const conn = pluginConn();
    (conn.properties as any).password = 'stored';
    expect(getIamAuth(conn, {})).toBeNull();
  });

  it('returns null when IAM auth is disabled via env', () => {
    expect(getIamAuth(pluginConn(), { OMNISQL_IAM_AUTH: 'false' })).toBeNull();
  });

  it('surfaces a config error (MISSING_USERNAME) for a misconfigured IAM connection', () => {
    const conn = pluginConn({ user: undefined });
    delete (conn.properties as any).user;
    expect(() => getIamAuth(conn, {})).toThrowError(
      expect.objectContaining({ kind: 'MISSING_USERNAME' })
    );
  });
});

describe('mintIamAuthToken', () => {
  const params = {
    profile: 'example-sso-profile',
    region: 'us-east-2',
    host: 'host.us-east-2.rds.amazonaws.com',
    port: 5432,
    database: 'postgres',
    username: 'app_user',
  };

  it('returns the token produced by the signer', async () => {
    const token = await mintIamAuthToken(params, {
      loadCredentials: () => ({ accessKeyId: 'AK', secretAccessKey: 'SK' }) as any,
      createSigner: (opts) => {
        expect(opts.hostname).toBe(params.host);
        expect(opts.username).toBe(params.username);
        expect(opts.region).toBe(params.region);
        return { getAuthToken: async () => 'minted-token-123' };
      },
    });
    expect(token).toBe('minted-token-123');
  });

  it('raises an AUTH_REQUIRED IamAuthError when the SSO session is expired', async () => {
    await expect(
      mintIamAuthToken(params, {
        loadCredentials: () => {
          throw new Error('Token is expired and refresh failed');
        },
        createSigner: () => ({ getAuthToken: async () => 'never' }),
      })
    ).rejects.toMatchObject({ kind: 'AUTH_REQUIRED', profile: 'example-sso-profile' });
  });

  it('classifies an SSO error thrown from getAuthToken (the real lazy-credential path) as AUTH_REQUIRED', async () => {
    await expect(
      mintIamAuthToken(params, {
        loadCredentials: () => ({ accessKeyId: 'AK', secretAccessKey: 'SK' }) as any,
        createSigner: () => ({
          getAuthToken: async () => {
            throw new Error(
              'The SSO session associated with this profile has expired or is otherwise invalid.'
            );
          },
        }),
      })
    ).rejects.toMatchObject({ kind: 'AUTH_REQUIRED', profile: 'example-sso-profile' });
  });

  it('does not misclassify an unrelated certificate-expiry error as AUTH_REQUIRED', async () => {
    await expect(
      mintIamAuthToken(params, {
        loadCredentials: () => ({ accessKeyId: 'AK', secretAccessKey: 'SK' }) as any,
        createSigner: () => ({
          getAuthToken: async () => {
            throw new Error('certificate has expired');
          },
        }),
      })
    ).rejects.toMatchObject({ kind: 'TOKEN_MINT_FAILED' });
  });

  it('raises a TOKEN_MINT_FAILED IamAuthError when the signer fails for an unrelated reason', async () => {
    await expect(
      mintIamAuthToken(params, {
        loadCredentials: () => ({ accessKeyId: 'AK', secretAccessKey: 'SK' }) as any,
        createSigner: () => ({
          getAuthToken: async () => {
            throw new Error('network unreachable');
          },
        }),
      })
    ).rejects.toMatchObject({ kind: 'TOKEN_MINT_FAILED' });
  });

  it('produces an IamAuthError instance', async () => {
    const err = await mintIamAuthToken(params, {
      loadCredentials: () => {
        throw new Error('Token is expired');
      },
      createSigner: () => ({ getAuthToken: async () => 'x' }),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(IamAuthError);
  });
});
