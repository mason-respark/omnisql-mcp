import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { DatabaseConnection } from '../src/types.js';

// Capture pg Pool configs to assert the IAM password function / SSL the pool builds.
const { pgPoolConfigs } = vi.hoisted(() => ({ pgPoolConfigs: [] as any[] }));
vi.mock('pg', () => ({
  Pool: class {
    constructor(config: any) {
      pgPoolConfigs.push(config);
    }
    async end() {}
  },
}));

const { mintMock } = vi.hoisted(() => ({ mintMock: vi.fn() }));
vi.mock('../src/iam-auth.js', async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return { ...actual, mintIamAuthToken: mintMock };
});

import { ConnectionPoolManager } from '../src/pools/connection-pool.js';

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

describe('ConnectionPoolManager — Aurora IAM auth', () => {
  let mgr: ConnectionPoolManager;

  beforeEach(() => {
    pgPoolConfigs.length = 0;
    mintMock.mockReset();
    delete process.env.OMNISQL_IAM_AUTH;
    mgr = new ConnectionPoolManager();
  });

  afterEach(() => {
    delete process.env.OMNISQL_IAM_AUTH;
    vi.restoreAllMocks();
  });

  it('gives an IAM pool a token-minting password function (rotates per connection)', async () => {
    mintMock.mockResolvedValue('pool-token');

    await mgr.getPool(iamConn());

    const cfg = pgPoolConfigs[0];
    expect(typeof cfg.password).toBe('function');
    await expect(cfg.password()).resolves.toBe('pool-token');
  });

  it('requires TLS for an IAM pool', async () => {
    mintMock.mockResolvedValue('pool-token');

    await mgr.getPool(iamConn());

    expect(pgPoolConfigs[0].ssl).toMatchObject({ rejectUnauthorized: true });
  });

  it('uses the stored password (string) for a stock Postgres pool', async () => {
    await mgr.getPool(stockPgConn());

    expect(typeof pgPoolConfigs[0].password).toBe('string');
    expect(pgPoolConfigs[0].password).toBe('hunter2');
    expect(mintMock).not.toHaveBeenCalled();
  });
});
