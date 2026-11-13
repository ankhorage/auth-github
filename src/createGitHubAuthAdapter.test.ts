import { expect, test } from 'bun:test';

import { createGitHubAuthAdapter } from './index.js';
import type { GitHubAuthConfig, GitHubAuthorizationAttempt } from './index.js';
import type { AuthSession } from '@ankhorage/contracts/auth';

/*** Provide a repeatable in-memory host for adapter boundary and HTTP transport tests. */
function createFixture(overrides: Partial<GitHubAuthConfig> = {}) {
  const attempts = new Map<string, GitHubAuthorizationAttempt>();
  const state: FixtureState = { session: null, now: 1_000, tokenCalls: [] };
  const config: GitHubAuthConfig = {
    clientId: 'client_id',
    clientSecret: 'server_secret',
    redirectUris: ['https://atlas.example/auth/callback'],
    createAttemptId: () => 'attempt_1',
    createState: () => 'state_1',
    now: () => state.now,
    fetcher: createTestFetcher(state),
    authorizationAttempts: createAttemptStore(attempts),
    sessions: createSessionStore(state),
    ...overrides,
  };
  return { adapter: createGitHubAuthAdapter(config), attempts, config, state };
}

interface FixtureState {
  session: AuthSession | null;
  now: number;
  tokenCalls: string[];
}

/*** Provide an HTTP simulation that rejects any unexpected GitHub endpoint. */
function createTestFetcher(state: FixtureState): typeof fetch {
  return (input, init) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL ? input.href : input.url;
    if (url === 'https://github.com/login/oauth/access_token')
      return Promise.resolve(tokenResponse(init, state));
    if (url === 'https://api.github.com/user')
      return Promise.resolve(userResponse(init));
    return Promise.reject(new Error('Unexpected external request'));
  };
}

/*** Simulate validated GitHub's user token and refresh response. */
function tokenResponse(init: RequestInit | undefined, state: FixtureState): Response {
  const data = init?.body instanceof URLSearchParams
    ? init.body
    : new URLSearchParams();
  state.tokenCalls.push(data.get('grant_type') ?? 'authorization_code');
  if (data.get('client_id') !== 'client_id' || data.get('client_secret') !== 'server_secret')
    return Response.json({ error: 'bad_client' }, { status: 401 });
  if (data.get('grant_type') === 'refresh_token' && data.get('refresh_token') !== 'refresh_1')
    return Response.json({ error: 'bad_refresh' }, { status: 401 });
  const refreshed = data.get('grant_type') === 'refresh_token';
  return Response.json({
    access_token: refreshed ? 'token_2' : 'token_1',
    refresh_token: refreshed ? 'refresh_2' : 'refresh_1',
    token_type: 'bearer',
    expires_in: 3_600,
  });
}

/*** Require the OAuth user profile request to carry the new bearer token. */
function userResponse(init: RequestInit | undefined): Response {
  if (!new Headers(init?.headers).get('Authorization')?.startsWith('Bearer token_'))
    return Response.json({}, { status: 401 });
  return Response.json({
    id: 42,
    login: 'verified-user',
    name: 'Verified User',
    avatar_url: 'https://avatars.githubusercontent.com/u/42',
  });
}

/*** Keep test authorization state single-use, atomic and independent of process memory. */
function createAttemptStore(attempts: Map<string, GitHubAuthorizationAttempt>):
GitHubAuthConfig['authorizationAttempts'] {
  return {
    create: (attempt) => {
      if (attempts.has(attempt.attemptId))
        return Promise.reject(new Error('duplicate'));
      attempts.set(attempt.attemptId, attempt);
      return Promise.resolve();
    },
    consume: (attemptId, now) => {
      const attempt = attempts.get(attemptId) ?? null;
      attempts.delete(attemptId);
      return Promise.resolve(attempt !== null && attempt.expiresAt > now ? attempt : null);
    },
    purgeExpired: (now) => {
      for (const [key, value] of attempts)
        if (value.expiresAt <= now) attempts.delete(key);
      return Promise.resolve();
    },
  };
}

/*** Keep the active session observable without an application framework. */
function createSessionStore(state: FixtureState): GitHubAuthConfig['sessions'] {
  return {
    get: () => Promise.resolve(state.session),
    save: (session) => { state.session = session; return Promise.resolve(); },
    clear: () => { state.session = null; return Promise.resolve(); },
  };
}

/*** Exercise the public OAuth happy path as a server request-scoped host would. */
async function start(fixture: ReturnType<typeof createFixture>) {
  return fixture.adapter.startAuthorization({
    provider: 'github', redirectUri: 'https://atlas.example/auth/callback',
  });
}

/*** Construct the configured callback with a synthetic one-time authorization code. */
function callback(code = 'code_1', state = 'state_1') {
  return {
    attemptId: 'attempt_1',
    response: { type: 'callback' as const,
      url: 'https://atlas.example/auth/callback?code=' + code + '&state=' + state },
  };
}

test('uses the canonical AuthPort and a confidential GitHub App authorization URL', async () => {
  const fixture = createFixture();
  expect(await fixture.adapter.getSession()).toEqual({ ok: true, data: null });
  const result = await start(fixture);
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
  expect(await fixture.adapter.startAuthorization({
    provider: 'google', redirectUri: 'https://atlas.example/auth/callback',
  })).toMatchObject({ ok: false, error: { code: 'provider_disabled' } });
  expect(await fixture.adapter.startAuthorization({
    provider: 'github', redirectUri: 'https://evil.example/callback',
  })).toMatchObject({ ok: false, error: { code: 'invalid_redirect_uri' } });
  expect(await fixture.adapter.startAuthorization({
    provider: 'github',
    redirectUri: 'https://atlas.example/auth/callback',
    scopes: ['repo'],
  })).toMatchObject({ ok: false, error: { code: 'authorization_failed' } });
  expect(fixture.attempts.size).toBe(0);
  expect(() => createFixture({ redirectUris: ['http://atlas.example/auth/callback'] }))
    .toThrow(/allowlisted HTTPS/);
});

test('safely requests optional offline_access without escalating repository scopes', async () => {
  const fixture = createFixture();
  const result = await fixture.adapter.startAuthorization({
    provider: 'github',
    redirectUri: 'https://atlas.example/auth/callback',
    scopes: ['offline_access'],
  });
  expect(result.ok).toBe(true);
  if (result.ok) expect(new URL(result.data.authorizationUrl).searchParams.get('scope'))
    .toBe('offline_access');
});

test('exchanges a code, verifies GitHub identity, and persists a token-bearing session', async () => {
  const fixture = createFixture();
  await start(fixture);
  const result = await fixture.adapter.completeAuthorization(callback());
  expect(result).toMatchObject({
    ok: true, status: 'authenticated', provider: 'github',
    session: {
      accessToken: 'token_1', refreshToken: 'refresh_1', expiresAt: 3_601_000,
      user: { id: '42', username: 'verified-user' },
    },
  });
  expect(await fixture.adapter.getSession()).toMatchObject({
    ok: true, data: { user: { id: '42' } },
  });
  expect(fixture.attempts.size).toBe(0);
  expect(fixture.state.tokenCalls).toEqual(['authorization_code']);
});

test('rejects callbacks with wrong state, wrong origin, or wrong path and consumes attempts', async () => {
  for (const bad of [
    callback('code_1', 'wrong'),
    { ...callback(), response: { type: 'callback' as const,
      url: 'https://evil.example/auth/callback?code=code_1&state=state_1' } },
    { ...callback(), response: { type: 'callback' as const,
      url: 'https://atlas.example/other?code=code_1&state=state_1' } },
    { ...callback(), response: { type: 'callback' as const,
      url: 'https://atlas.example/auth/callback?code=x&state=state_1&state=state_1' } },
  ]) {
    const fixture = createFixture();
    await start(fixture);
    const result = await fixture.adapter.completeAuthorization(bad);
    expect(result.ok).toBe(false);
    expect(fixture.attempts.size).toBe(0);
    expect(fixture.state.tokenCalls).toHaveLength(0);
  }
});

test('rejects expired, replayed, and concurrently replayed callback attempts', async () => {
  const fixture = createFixture();
  await start(fixture);
  const [first, second] = await Promise.all([
    fixture.adapter.completeAuthorization(callback()),
    fixture.adapter.completeAuthorization(callback()),
  ]);
  expect([first, second].filter(x => x.ok)).toHaveLength(1);
  expect([first, second].filter(x => !x.ok)).toHaveLength(1);
  expect(await fixture.adapter.completeAuthorization(callback())).toMatchObject({
    ok: false, error: { code: 'authorization_attempt_not_found' },
  });
  const expired = createFixture({ authorizationAttemptTtlMs: 1 });
  await start(expired);
  expired.state.now = 1_002;
  expect(await expired.adapter.completeAuthorization(callback())).toMatchObject({
    ok: false, error: { code: 'authorization_attempt_not_found' },
  });
});

test('treats GitHub denial as cancellation without requesting a token', async () => {
  const fixture = createFixture();
  await start(fixture);
  expect(await fixture.adapter.completeAuthorization({
    attemptId: 'attempt_1',
    response: { type: 'callback',
      url: 'https://atlas.example/auth/callback?error=access_denied&state=state_1' },
  })).toMatchObject({
    ok: false, status: 'cancelled', reason: 'provider_denied',
  });
  expect(fixture.state.tokenCalls).toHaveLength(0);
});

test('refreshes expiring GitHub App tokens, rotates stored tokens, and preserves user identity', async () => {
  const fixture = createFixture();
  await start(fixture);
  await fixture.adapter.completeAuthorization(callback());
  const refreshed = await fixture.adapter.refreshSession();
  expect(refreshed).toMatchObject({
    ok: true, data: { accessToken: 'token_2', refreshToken: 'refresh_2',
      user: { id: '42' } },
  });
  expect(fixture.state.tokenCalls).toEqual(['authorization_code', 'refresh_token']);
  expect(fixture.state.session?.accessToken).toBe('token_2');
  fixture.state.now = 3_601_001;
  expect(await fixture.adapter.getSession()).toMatchObject({ ok: true, data: null });
});

test('fails closed when refreshed GitHub identity is different', async () => {
  const fixture = createFixture();
  fixture.state.session = { accessToken: 'old', refreshToken: 'refresh_1',
    user: { id: 'different-user' } };
  expect(await fixture.adapter.refreshSession()).toMatchObject({
    ok: false, error: { code: 'invalid_session' },
  });
  expect(fixture.state.session.accessToken).toBe('old');
});

test('returns secret-free errors on provider and persistence failures', async () => {
  const fixture = createFixture({
    fetcher: async () => { throw new Error('server_secret code_1 token_1'); },
  });
  await start(fixture);
  const result = await fixture.adapter.completeAuthorization(callback());
  expect(result).toMatchObject({ ok: false, error: { code: 'code_exchange_failed' } });
  expect(JSON.stringify(result)).not.toContain('server_secret');
  const failedStore = createFixture({
    authorizationAttempts: {
      create: async () => { throw new Error('server_secret'); },
      purgeExpired: async () => {},
      consume: async () => { throw new Error('server_secret'); },
    },
  });
  expect(await start(failedStore)).toMatchObject({ ok: false, error: { code: 'authorization_failed' } });
  expect(await failedStore.adapter.completeAuthorization(callback())).toMatchObject({
    ok: false, error: { code: 'authorization_attempt_not_found' },
  });
});

test('provides local sign-out and explicitly rejects password, OTP, and global sign-out', async () => {
  const fixture = createFixture();
  expect(await fixture.adapter.signIn({ identifier: { kind: 'username', value: 'u' } }))
    .toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(await fixture.adapter.signUp({ identifier: { kind: 'email', value: 'a@example.com' } }))
    .toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(await fixture.adapter.requestPasswordReset({ identifier: { kind: 'email', value: 'a@example.com' } }))
    .toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(await fixture.adapter.verifyOtp({ identifier: { kind: 'email', value: 'a@example.com' }, token: 'x' }))
    .toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  fixture.state.session = { accessToken: 'token_1', user: { id: '42' } };
  expect(await fixture.adapter.signOut({ allDevices: true }))
    .toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(fixture.state.session).not.toBeNull();
  expect(await fixture.adapter.signOut()).toEqual({ ok: true });
  expect(fixture.state.session).toBeNull();
});

test('retains a non-expiring OAuth session without a refresh token', async () => {
  const fixture = createFixture();
  fixture.state.session = { accessToken: 'classic-token', user: { id: '42' } };
  expect(await fixture.adapter.refreshSession()).toEqual({
    ok: true, data: fixture.state.session,
  });
});
