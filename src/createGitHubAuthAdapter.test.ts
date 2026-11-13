import { expect, test } from 'bun:test';

import {
  createCallback,
  createFixture,
  startAuthorizationAsync,
} from './createGitHubAuthAdapter.fixture.js';

test('uses the canonical AuthPort and a confidential GitHub App authorization URL', async () => {
  const fixture = createFixture();
  expect(await fixture.adapter.getSession()).toEqual({ ok: true, data: null });
  const result = await startAuthorizationAsync(fixture);
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const url = new URL(result.data.authorizationUrl);
  expect(url.origin).toBe('https://github.com');
  expect(url.pathname).toBe('/login/oauth/authorize');
  expect(url.searchParams.get('client_id')).toBe('client_id');
  expect(url.searchParams.get('state')).toBe('state_1');
  expect(url.searchParams.get('redirect_uri')).toBe('https://atlas.example/auth/callback');
  expect(result.data.authorizationUrl).not.toContain('server_secret');
  expect(fixture.attempts.size).toBe(1);
});

test('allows only GitHub and exact server-registered HTTPS callbacks', async () => {
  const fixture = createFixture();
  expect(
    await fixture.adapter.startAuthorization({
      provider: 'google',
      redirectUri: 'https://atlas.example/auth/callback',
    }),
  ).toMatchObject({ ok: false, error: { code: 'provider_disabled' } });
  expect(
    await fixture.adapter.startAuthorization({
      provider: 'github',
      redirectUri: 'https://evil.example/callback',
    }),
  ).toMatchObject({ ok: false, error: { code: 'invalid_redirect_uri' } });
  expect(
    await fixture.adapter.startAuthorization({
      provider: 'github',
      redirectUri: 'https://atlas.example/auth/callback',
      scopes: ['repo'],
    }),
  ).toMatchObject({ ok: false, error: { code: 'authorization_failed' } });
  expect(fixture.attempts.size).toBe(0);
  expect(() => createFixture({ redirectUris: ['http://atlas.example/auth/callback'] })).toThrow(
    /allowlisted HTTPS/,
  );
});

test('limits GitHub App authorization to its documented renewal scope', async () => {
  const fixture = createFixture();
  const result = await fixture.adapter.startAuthorization({
    provider: 'github',
    redirectUri: 'https://atlas.example/auth/callback',
    scopes: ['offline_access'],
  });
  expect(result.ok).toBe(true);
  if (result.ok)
    expect(new URL(result.data.authorizationUrl).searchParams.get('scope')).toBe('offline_access');
});

test('starts a classic OAuth App login with read:user and an explicit optional repo scope', async () => {
  const fixture = createFixture({ authorizationMode: 'oauth-app' });
  const regular = await fixture.adapter.startAuthorization({
    provider: 'github',
    redirectUri: 'https://atlas.example/auth/callback',
    scopes: ['read:user'],
  });
  expect(regular.ok).toBe(true);
  if (regular.ok)
    expect(new URL(regular.data.authorizationUrl).searchParams.get('scope')).toBe('read:user');

  const repositoryFixture = createFixture({ authorizationMode: 'oauth-app' });
  const repositoryAccess = await repositoryFixture.adapter.startAuthorization({
    provider: 'github',
    redirectUri: 'https://atlas.example/auth/callback',
    scopes: ['read:user', 'repo'],
  });
  expect(repositoryAccess.ok).toBe(true);
  if (repositoryAccess.ok)
    expect(new URL(repositoryAccess.data.authorizationUrl).searchParams.get('scope')).toBe(
      'read:user repo',
    );
});

test('rejects scope escalation across GitHub authorization modes', async () => {
  const classic = createFixture({ authorizationMode: 'oauth-app' });
  expect(
    await classic.adapter.startAuthorization({
      provider: 'github',
      redirectUri: 'https://atlas.example/auth/callback',
      scopes: ['admin:org'],
    }),
  ).toMatchObject({ ok: false, error: { code: 'authorization_failed' } });
  expect(
    await classic.adapter.startAuthorization({
      provider: 'github',
      redirectUri: 'https://atlas.example/auth/callback',
      scopes: ['repo'],
    }),
  ).toMatchObject({ ok: false, error: { code: 'authorization_failed' } });
  const app = createFixture();
  expect(
    await app.adapter.startAuthorization({
      provider: 'github',
      redirectUri: 'https://atlas.example/auth/callback',
      scopes: ['read:user'],
    }),
  ).toMatchObject({ ok: false, error: { code: 'authorization_failed' } });
});

test('exchanges a code, verifies GitHub identity, and persists a token-bearing session', async () => {
  const fixture = createFixture();
  await startAuthorizationAsync(fixture);
  const result = await fixture.adapter.completeAuthorization(createCallback());
  expect(result).toMatchObject({
    ok: true,
    status: 'authenticated',
    provider: 'github',
    session: {
      accessToken: 'token_1',
      refreshToken: 'refresh_1',
      expiresAt: 3_601_000,
      user: { id: '42', username: 'verified-user' },
    },
  });
  expect(await fixture.adapter.getSession()).toMatchObject({
    ok: true,
    data: { user: { id: '42' } },
  });
  expect(fixture.attempts.size).toBe(0);
  expect(fixture.state.tokenCalls).toEqual(['authorization_code']);
});

test('rejects callbacks with wrong state, wrong origin, or wrong path and consumes attempts', async () => {
  for (const bad of [
    createCallback('code_1', 'wrong'),
    {
      ...createCallback(),
      response: {
        type: 'callback' as const,
        url: 'https://evil.example/auth/callback?code=code_1&state=state_1',
      },
    },
    {
      ...createCallback(),
      response: {
        type: 'callback' as const,
        url: 'https://atlas.example/other?code=code_1&state=state_1',
      },
    },
    {
      ...createCallback(),
      response: {
        type: 'callback' as const,
        url: 'https://atlas.example/auth/callback?code=x&state=state_1&state=state_1',
      },
    },
  ]) {
    const fixture = createFixture();
    await startAuthorizationAsync(fixture);
    const result = await fixture.adapter.completeAuthorization(bad);
    expect(result.ok).toBe(false);
    expect(fixture.attempts.size).toBe(0);
    expect(fixture.state.tokenCalls).toHaveLength(0);
  }
});

test('rejects expired, replayed, and concurrently replayed callback attempts', async () => {
  const fixture = createFixture();
  await startAuthorizationAsync(fixture);
  const [first, second] = await Promise.all([
    fixture.adapter.completeAuthorization(createCallback()),
    fixture.adapter.completeAuthorization(createCallback()),
  ]);
  expect([first, second].filter((x) => x.ok)).toHaveLength(1);
  expect([first, second].filter((x) => !x.ok)).toHaveLength(1);
  expect(await fixture.adapter.completeAuthorization(createCallback())).toMatchObject({
    ok: false,
    error: { code: 'authorization_attempt_not_found' },
  });
  const expired = createFixture({ authorizationAttemptTtlMs: 1 });
  await startAuthorizationAsync(expired);
  expired.state.now = 1_002;
  expect(await expired.adapter.completeAuthorization(createCallback())).toMatchObject({
    ok: false,
    error: { code: 'authorization_attempt_not_found' },
  });
});

test('treats GitHub denial as cancellation without requesting a token', async () => {
  const fixture = createFixture();
  await startAuthorizationAsync(fixture);
  expect(
    await fixture.adapter.completeAuthorization({
      attemptId: 'attempt_1',
      response: {
        type: 'callback',
        url: 'https://atlas.example/auth/callback?error=access_denied&state=state_1',
      },
    }),
  ).toMatchObject({
    ok: false,
    status: 'cancelled',
    reason: 'provider_denied',
  });
  expect(fixture.state.tokenCalls).toHaveLength(0);
});

test('refreshes expiring GitHub App tokens, rotates stored tokens, and preserves user identity', async () => {
  const fixture = createFixture();
  await startAuthorizationAsync(fixture);
  await fixture.adapter.completeAuthorization(createCallback());
  const refreshed = await fixture.adapter.refreshSession();
  expect(refreshed).toMatchObject({
    ok: true,
    data: { accessToken: 'token_2', refreshToken: 'refresh_2', user: { id: '42' } },
  });
  expect(fixture.state.tokenCalls).toEqual(['authorization_code', 'refresh_token']);
  expect(fixture.state.session?.accessToken).toBe('token_2');
  fixture.state.now = 3_601_001;
  expect(await fixture.adapter.getSession()).toMatchObject({ ok: true, data: null });
});

test('fails closed when refreshed GitHub identity is different', async () => {
  const fixture = createFixture();
  fixture.state.session = {
    accessToken: 'old',
    refreshToken: 'refresh_1',
    user: { id: 'different-user' },
  };
  expect(await fixture.adapter.refreshSession()).toMatchObject({
    ok: false,
    error: { code: 'invalid_session' },
  });
  expect(fixture.state.session.accessToken).toBe('old');
});

test('returns secret-free errors on provider and persistence failures', async () => {
  const fixture = createFixture({
    fetcher: () => Promise.reject(new Error('server_secret code_1 token_1')),
  });
  await startAuthorizationAsync(fixture);
  const result = await fixture.adapter.completeAuthorization(createCallback());
  expect(result).toMatchObject({ ok: false, error: { code: 'code_exchange_failed' } });
  expect(JSON.stringify(result)).not.toContain('server_secret');
  const failedStore = createFixture({
    authorizationAttempts: {
      create: () => Promise.reject(new Error('server_secret')),
      purgeExpired: () => Promise.resolve(),
      consume: () => Promise.reject(new Error('server_secret')),
    },
  });
  expect(await startAuthorizationAsync(failedStore)).toMatchObject({
    ok: false,
    error: { code: 'authorization_failed' },
  });
  expect(await failedStore.adapter.completeAuthorization(createCallback())).toMatchObject({
    ok: false,
    error: { code: 'authorization_attempt_not_found' },
  });
});

test('provides local sign-out and explicitly rejects password, OTP, and global sign-out', async () => {
  const fixture = createFixture();
  expect(
    await fixture.adapter.signIn({ identifier: { kind: 'username', value: 'u' } }),
  ).toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(
    await fixture.adapter.signUp({ identifier: { kind: 'email', value: 'a@example.com' } }),
  ).toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(
    await fixture.adapter.requestPasswordReset({
      identifier: { kind: 'email', value: 'a@example.com' },
    }),
  ).toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(
    await fixture.adapter.verifyOtp({
      identifier: { kind: 'email', value: 'a@example.com' },
      token: 'x',
    }),
  ).toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  fixture.state.session = { accessToken: 'token_1', user: { id: '42' } };
  expect(await fixture.adapter.signOut({ allDevices: true })).toMatchObject({
    ok: false,
    error: { code: 'unsupported_operation' },
  });
  expect(fixture.state.session).not.toBeNull();
  expect(await fixture.adapter.signOut()).toEqual({ ok: true });
  expect(fixture.state.session).toBeNull();
});

test('retains a non-expiring OAuth session without a refresh token', async () => {
  const fixture = createFixture();
  fixture.state.session = { accessToken: 'classic-token', user: { id: '42' } };
  expect(await fixture.adapter.refreshSession()).toEqual({
    ok: true,
    data: fixture.state.session,
  });
});
