import type {
  AuthorizationAttempt,
  AuthorizationAttemptPersistencePort,
  DurableSession,
  SessionPersistencePort,
} from '@ankhorage/auth/persistence';
import type { AuthSession } from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig } from './index.js';
import { createGitHubAuthAdapter } from './index.js';

/*** Provide a repeatable in-memory host for adapter boundary and HTTP transport tests. */
export function createFixture(overrides: Partial<GitHubAuthConfig> = {}) {
  const attempts = new Map<string, AuthorizationAttempt>();
  const sessions = new Map<string, DurableSession>();
  const state: FixtureState = {
    session: null,
    sessionId: 'browser_1',
    nextSessionId: 2,
    now: 1_000,
    tokenCalls: [],
  };
  const config = createFixtureConfig(state, attempts, sessions, overrides);
  return {
    adapter: createGitHubAuthAdapter(config),
    attempts,
    sessions,
    config,
    state,
    setSession: (session: AuthSession) => setFixtureSession(sessions, state, session),
  };
}

/*** Assemble a server-scoped GitHub adapter configuration backed only by deterministic test ports. */
function createFixtureConfig(
  state: FixtureState,
  attempts: Map<string, AuthorizationAttempt>,
  sessions: Map<string, DurableSession>,
  overrides: Partial<GitHubAuthConfig>,
): GitHubAuthConfig {
  return {
    authorizationMode: 'github-app',
    clientId: 'client_id',
    clientSecret: 'server_secret',
    redirectUris: ['https://atlas.example/auth/callback'],
    createAttemptId: () => 'attempt_1',
    createSessionId: () => {
      const sessionId = 'session_' + state.nextSessionId;
      state.nextSessionId += 1;
      return sessionId;
    },
    createState: () => 'state_1',
    now: () => state.now,
    fetcher: createTestFetcher(state),
    authorizationAttempts: createAttemptStore(attempts),
    sessions: createSessionStore(sessions, state),
    session: {
      get sessionId() {
        return state.sessionId;
      },
      replaceSessionId: (sessionId) => {
        state.sessionId = sessionId;
        return Promise.resolve();
      },
      clearSessionId: () => {
        state.sessionId = '';
        return Promise.resolve();
      },
    },
    payloadEncryption: {
      encrypt: (payload) => Promise.resolve({ ciphertext: JSON.stringify(payload) }),
      decrypt: (payload) => Promise.resolve(JSON.parse(payload.ciphertext) as unknown),
    },
    ...overrides,
  };
}

interface FixtureState {
  session: AuthSession | null;
  sessionId: string;
  nextSessionId: number;
  now: number;
  tokenCalls: string[];
}

/*** Seed one durable session for a focused adapter test without creating a production fallback. */
function setFixtureSession(
  sessions: Map<string, DurableSession>,
  state: FixtureState,
  session: AuthSession,
): void {
  const durableSession: DurableSession = {
    sessionId: state.sessionId,
    subject: { userId: session.user.id },
    encryptedPayload: { ciphertext: JSON.stringify(session) },
    createdAt: state.now,
    expiresAt: session.expiresAt ?? 8_640_000_000_000_000,
  };
  sessions.set(durableSession.sessionId, durableSession);
  state.session = session;
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
  attempts: Map<string, AuthorizationAttempt>,
): AuthorizationAttemptPersistencePort {
  return {
    create: (attempt) => {
      if (attempts.has(attempt.attemptId)) return Promise.reject(new Error('duplicate'));
      attempts.set(attempt.attemptId, attempt);
      return Promise.resolve({ status: 'created' });
    },
    consume: ({ attemptId, sessionId, now }) => {
      const attempt = attempts.get(attemptId);
      attempts.delete(attemptId);
      if (attempt === undefined) return Promise.resolve({ status: 'not_found' });
      if (attempt.expiresAt <= now) return Promise.resolve({ status: 'expired' });
      if (attempt.sessionId !== sessionId) return Promise.resolve({ status: 'session_mismatch' });
      return Promise.resolve({ status: 'consumed', attempt });
    },
  };
}

/*** Keep the active session observable without an application framework. */
function createSessionStore(
  sessions: Map<string, DurableSession>,
  state: FixtureState,
): SessionPersistencePort {
  return {
    create: (session) => {
      if (sessions.has(session.sessionId))
        return Promise.resolve({ status: 'identifier_conflict' });
      sessions.set(session.sessionId, session);
      state.session = decryptSession(session);
      return Promise.resolve({ status: 'created' });
    },
    read: (sessionId, now) => {
      const session = sessions.get(sessionId);
      if (session === undefined) return Promise.resolve({ status: 'not_found' });
      if (session.expiresAt <= now) return Promise.resolve({ status: 'expired' });
      return Promise.resolve({ status: 'found', session });
    },
    revoke: ({ sessionId, subject }) => {
      const session = sessions.get(sessionId);
      if (session === undefined) return Promise.resolve({ status: 'not_found' });
      if (session.subject.userId !== subject.userId)
        return Promise.resolve({ status: 'subject_mismatch' });
      sessions.delete(sessionId);
      state.session = null;
      return Promise.resolve({ status: 'revoked' });
    },
    rotate: ({ replacedSessionId, replacement, subject }) => {
      const session = sessions.get(replacedSessionId);
      if (session === undefined) return Promise.resolve({ status: 'not_found' });
      if (session.subject.userId !== subject.userId)
        return Promise.resolve({ status: 'subject_mismatch' });
      if (sessions.has(replacement.sessionId))
        return Promise.resolve({ status: 'replacement_identifier_conflict' });
      sessions.delete(replacedSessionId);
      sessions.set(replacement.sessionId, replacement);
      state.session = decryptSession(replacement);
      return Promise.resolve({ status: 'rotated' });
    },
  };
}

/*** Decode fixture-only encrypted session data after the test persistence boundary accepts it. */
function decryptSession(session: DurableSession): AuthSession {
  return JSON.parse(session.encryptedPayload.ciphertext) as AuthSession;
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
