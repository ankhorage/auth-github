import type { AuthSession } from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig, GitHubAuthorizationAttempt } from './index.js';
import { createGitHubAuthAdapter } from './index.js';

/*** Provide a repeatable in-memory host for adapter boundary and HTTP transport tests. */
export function createFixture(overrides: Partial<GitHubAuthConfig> = {}) {
  const attempts = new Map<string, GitHubAuthorizationAttempt>();
  const state: FixtureState = { session: null, now: 1_000, tokenCalls: [] };
  const config: GitHubAuthConfig = {
    authorizationMode: 'github-app',
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
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url === 'https://github.com/login/oauth/access_token')
      return Promise.resolve(tokenResponse(init, state));
    if (url === 'https://api.github.com/user') return Promise.resolve(userResponse(init));
    return Promise.reject(new Error('Unexpected external request'));
  };
}

/*** Simulate validated GitHub's user token and refresh response. */
function tokenResponse(init: RequestInit | undefined, state: FixtureState): Response {
  const data = init?.body instanceof URLSearchParams ? init.body : new URLSearchParams();
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
function createAttemptStore(
  attempts: Map<string, GitHubAuthorizationAttempt>,
): GitHubAuthConfig['authorizationAttempts'] {
  return {
    create: (attempt) => {
      if (attempts.has(attempt.attemptId)) return Promise.reject(new Error('duplicate'));
      attempts.set(attempt.attemptId, attempt);
      return Promise.resolve();
    },
    consume: (attemptId, now) => {
      const attempt = attempts.get(attemptId) ?? null;
      attempts.delete(attemptId);
      return Promise.resolve(attempt !== null && attempt.expiresAt > now ? attempt : null);
    },
    purgeExpired: (now) => {
      for (const [key, value] of attempts) if (value.expiresAt <= now) attempts.delete(key);
      return Promise.resolve();
    },
  };
}

/*** Keep the active session observable without an application framework. */
function createSessionStore(state: FixtureState): GitHubAuthConfig['sessions'] {
  return {
    get: () => Promise.resolve(state.session),
    save: (session) => {
      state.session = session;
      return Promise.resolve();
    },
    clear: () => {
      state.session = null;
      return Promise.resolve();
    },
  };
}

/*** Exercise the public OAuth happy path as a server request-scoped host would. */
export async function startAuthorizationAsync(fixture: ReturnType<typeof createFixture>) {
  return fixture.adapter.startAuthorization({
    provider: 'github',
    redirectUri: 'https://atlas.example/auth/callback',
  });
}

/*** Construct the configured callback with a synthetic one-time authorization code. */
export function createCallback(code = 'code_1', state = 'state_1') {
  return {
    attemptId: 'attempt_1',
    response: {
      type: 'callback' as const,
      url: 'https://atlas.example/auth/callback?code=' + code + '&state=' + state,
    },
  };
}
