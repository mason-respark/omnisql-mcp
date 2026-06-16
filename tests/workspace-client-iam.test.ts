import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { DatabaseConnection } from '../src/types.js';

// Capture every pg Client config so we can assert the password/ssl the IAM path injects.
const { pgConfigs } = vi.hoisted(() => ({ pgConfigs: [] as any[] }));
vi.mock('pg', () => ({
  Client: class {
    constructor(config: any) {
      pgConfigs.push(config);
    }
    async connect() {}
    async query() {
      return { fields: [{ name: 'ok' }], rows: [{ ok: 1 }], rowCount: 1 };
    }
    async end() {}
  },
}));

// Spy the token minter but keep the real detection/resolution logic.
const { mintMock } = vi.hoisted(() => ({ mintMock: vi.fn() }));
vi.mock('../src/iam-auth.js', async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return { ...actual, mintIamAuthToken: mintMock };
});

import { WorkspaceClient } from '../src/workspace-client.js';
import { IamAuthError } from '../src/iam-auth.js';

function iamConn(overrides: Partial<DatabaseConnection> = {}): DatabaseConnection {
  return {
    id: 'aurora-pg-1',
    name: 'aurora_pg_prod',
    driver: 'aurora-postgresql',
    url: '',
    host: 'infra.cluster-x.us-east-2.rds.amazonaws.com',
    port: 5432,
    database: 'postgres',
    user: 'app_user',
    properties: {
      properties: {
        awsProfile: 'example-sso-profile',
        iamRegion: 'us-east-2',
        sslrootcert: '/tmp/does-not-exist-ca.pem',
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

describe('WorkspaceClient — Aurora IAM auth on the Postgres path', () => {
  let client: WorkspaceClient;

  beforeEach(() => {
    pgConfigs.length = 0;
    mintMock.mockReset();
    delete process.env.OMNISQL_IAM_AUTH;
    client = new WorkspaceClient(undefined, 5000, false, '/tmp/fake-ws');
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.OMNISQL_IAM_AUTH;
  });

  it('mints an IAM token and uses it as the Postgres password', async () => {
    mintMock.mockResolvedValue('minted-token-xyz');

    await client.executeQuery(iamConn(), 'SELECT 1');

    expect(mintMock).toHaveBeenCalledTimes(1);
    expect(pgConfigs[0].password).toBe('minted-token-xyz');
  });

  it('forces TLS for an IAM connection even when no sslmode is persisted', async () => {
    mintMock.mockResolvedValue('minted-token-xyz');

    await client.executeQuery(iamConn(), 'SELECT 1');

    // Plugin-shape connections persist no sslmode; IAM must still connect over TLS.
    expect(pgConfigs[0].ssl).toBeTruthy();
    expect(pgConfigs[0].ssl).not.toBe(false);
  });

  it('does not mint when a stored password is already present', async () => {
    const conn = iamConn();
    (conn.properties as any).password = 'stored-pw';

    await client.executeQuery(conn, 'SELECT 1');

    expect(mintMock).not.toHaveBeenCalled();
    expect(pgConfigs[0].password).toBe('stored-pw');
  });

  it('propagates an AUTH_REQUIRED IamAuthError unwrapped (not "Query execution failed")', async () => {
    mintMock.mockRejectedValue(
      new IamAuthError('AUTH_REQUIRED', 'SSO session expired', { profile: 'example-sso-profile' })
    );

    const err = await client.executeQuery(iamConn(), 'SELECT 1').catch((e) => e);
    expect(err).toBeInstanceOf(IamAuthError);
    expect(err.kind).toBe('AUTH_REQUIRED');
  });

  it('skips IAM minting when OMNISQL_IAM_AUTH=false', async () => {
    process.env.OMNISQL_IAM_AUTH = 'false';

    await client.executeQuery(iamConn(), 'SELECT 1');

    expect(mintMock).not.toHaveBeenCalled();
  });

  it('does not trigger IAM minting for a stock Postgres connection', async () => {
    await client.executeQuery(stockPgConn(), 'SELECT 1');

    expect(mintMock).not.toHaveBeenCalled();
    expect(pgConfigs[0].password).toBe('hunter2');
  });
});
