import type { AuthPort } from '@ankhorage/auth';
import type {
  AuthOAuthCompletionResult,
  AuthOAuthError,
  AuthOAuthStartResult,
  AuthResult,
  AuthSession,
  AuthUser,
} from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig, GitHubAuthorizationAttempt } from '../../../../types/github.js';
import { createGitHubOAuthGateway } from './createGitHubOAuthGateway.js';

const DEFAULT_TTL_MS = 10 * 60 * 1_000;

/*** Implement Ankhorage AuthPort with GitHub App user OAuth and caller-owned durable stores. */
export function createGitHubAuthAdapter(config: GitHubAuthConfig): AuthPort {
  validateConfig(config);
  const now = config.now ?? Date.now;
  const makeAttemptId = config.createAttemptId ?? crypto.randomUUID;
  const makeState = config.createState ?? crypto.randomUUID;
  const gateway = createGitHubOAuthGateway(config);
  const unsupported = <T>(): AuthResult<T> => ({
    ok: false,
    error: { code: 'unsupported_operation', message: 'GitHub uses browser authorization.' },
  });

  return {
    signIn: () => Promise.resolve(unsupported<AuthSession>()),
    signUp: () => Promise.resolve(unsupported<AuthSession | AuthUser>()),
    signOut: async (input) => {
      if (input?.allDevices)
        return { ok: false, error: { code: 'unsupported_operation', message: 'Global sign-out is not supported.' } };
      try {
        await config.sessions.clear();
        return { ok: true };
      } catch {
        return sessionError('Unable to end the local session.');
      }
    },
    getSession: async () => {
      try {
        const session = await config.sessions.get();
        return { ok: true, data: session?.expiresAt !== undefined && session.expiresAt <= now() ? null : session };
      } catch {
        return sessionError('Unable to read the local session.');
      }
    },
    refreshSession: async () => {
      try {
        const session = await config.sessions.get();
        if (session === null) return { ok: true, data: null };
        if (!session.refreshToken) {
          return session.expiresAt === undefined || session.expiresAt > now()
            ? { ok: true, data: session }
            : sessionError('GitHub authorization has expired.');
        }
        const refreshed = await gateway.refreshTokenAsync(session.refreshToken, session.user.id);
        await config.sessions.save(refreshed);
        return { ok: true, data: refreshed };
      } catch {
        return sessionError('GitHub session refresh failed.');
      }
    },
    requestPasswordReset: () => Promise.resolve(unsupported<void>()),
    verifyOtp: () => Promise.resolve(unsupported<AuthSession>()),
    startAuthorization: async (input) => {
      if (input.provider !== 'github') return oauthStartError('provider_disabled', 'GitHub is the only supported provider.');
      if (!config.redirectUris.includes(input.redirectUri))
        return oauthStartError('invalid_redirect_uri', 'The callback URL is not allowlisted.');
      if (input.scopes?.some(scope => scope !== 'offline_access') ||
          (input.queryParams !== undefined && Object.keys(input.queryParams).length > 0))
        return oauthStartError('authorization_failed', 'Unsupported GitHub App authorization parameters.');
      const attempt: GitHubAuthorizationAttempt = {
        attemptId: makeAttemptId(),
        state: makeState(),
        redirectUri: input.redirectUri,
        expiresAt: now() + (config.authorizationAttemptTtlMs ?? DEFAULT_TTL_MS),
      };
      try {
        await config.authorizationAttempts.purgeExpired(now());
        await config.authorizationAttempts.create(attempt);
        const url = new URL('https://github.com/login/oauth/authorize');
        url.searchParams.set('client_id', config.clientId);
        url.searchParams.set('redirect_uri', attempt.redirectUri);
        url.searchParams.set('state', attempt.state);
        if (input.scopes?.includes('offline_access')) url.searchParams.set('scope', 'offline_access');
        return { ok: true, data: {
          attemptId: attempt.attemptId,
          provider: 'github',
          redirectUri: attempt.redirectUri,
          authorizationUrl: url.toString(),
        } };
      } catch {
        return oauthStartError('authorization_failed', 'Unable to start GitHub authorization.');
      }
    },
    completeAuthorization: async (input): Promise<AuthOAuthCompletionResult> => {
      const attempt = await consumeAttemptAsync(config, input.attemptId, now());
      if (attempt === null) return oauthError('authorization_attempt_not_found', 'callback');
      if (input.response.type === 'cancelled')
        return { ok: false, status: 'cancelled', provider: 'github', reason: input.response.reason };
      if (input.response.type === 'error') return oauthError('provider_error', 'transport');
      const callback = parseCallback(input.response.url, attempt.redirectUri);
      if (callback === null) return oauthError('invalid_callback', 'callback');
      if (callback.state !== attempt.state) return oauthError('state_mismatch', 'callback');
      if (callback.error === 'access_denied')
        return { ok: false, status: 'cancelled', provider: 'github', reason: 'provider_denied' };
      if (callback.error !== undefined) return oauthError('provider_error', 'callback');
      if (callback.code === undefined) return oauthError('invalid_callback', 'callback');
      try {
        const session = await gateway.exchangeCodeAsync(callback.code, attempt.redirectUri);
        try {
          await config.sessions.save(session);
        } catch {
          return oauthError('session_persistence_failed', 'session');
        }
        return { ok: true, status: 'authenticated', provider: 'github', session };
      } catch {
        return oauthError('code_exchange_failed', 'exchange');
      }
    },
  };
}

/*** Validate confidential GitHub configuration before creating a reusable adapter. */
function validateConfig(config: GitHubAuthConfig): void {
  if (!config.clientId.trim() || !config.clientSecret.trim() || config.redirectUris.length === 0 ||
      (config.authorizationAttemptTtlMs !== undefined &&
        (!Number.isSafeInteger(config.authorizationAttemptTtlMs) || config.authorizationAttemptTtlMs < 1)) ||
      (config.requestTimeoutMs !== undefined &&
        (!Number.isSafeInteger(config.requestTimeoutMs) || config.requestTimeoutMs < 1))) {
    throw new Error('Invalid GitHub App authorization configuration.');
  }
  for (const item of config.redirectUris) {
    try {
      const url = new URL(item);
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
          url.toString() !== item)
        throw new Error('Invalid callback.');
    } catch {
      throw new Error('GitHub OAuth callback URLs must be explicitly allowlisted HTTPS URLs.');
    }
  }
}

/*** Atomically retire one authorization attempt regardless of callback outcome. */
async function consumeAttemptAsync(
  config: GitHubAuthConfig,
  attemptId: string,
  now: number
): Promise<GitHubAuthorizationAttempt | null> {
  try {
    return await config.authorizationAttempts.consume(attemptId, now);
  } catch {
    return null;
  }
}

/*** Match the exact registered callback path and one opaque state before accepting a code. */
function parseCallback(
  urlText: string,
  redirectUri: string
): { readonly state: string; readonly code?: string; readonly error?: string } | null {
  try {
    const actual = new URL(urlText);
    const expected = new URL(redirectUri);
    if (actual.origin !== expected.origin || actual.pathname !== expected.pathname ||
        actual.hash !== '' || actual.searchParams.getAll('state').length !== 1 ||
        actual.searchParams.getAll('code').length > 1 ||
        actual.searchParams.getAll('error').length > 1)
      return null;
    const state = actual.searchParams.get('state');
    if (!state) return null;
    const code = actual.searchParams.get('code');
    const error = actual.searchParams.get('error');
    return { state, ...(code ? { code } : {}), ...(error ? { error } : {}) };
  } catch {
    return null;
  }
}

/*** Return a generic OAuth error without provider secrets, URLs or codes. */
function oauthError(
  code: AuthOAuthError['code'],
  stage: AuthOAuthError['stage']
): AuthOAuthCompletionResult {
  return { ok: false, status: 'error', error: {
    code, stage, provider: 'github', recoverable: false,
    message: 'GitHub authorization failed.',
  } };
}

/*** Return a safe error for authorization start failures. */
function oauthStartError(
  code: AuthOAuthError['code'],
  message: string
): AuthOAuthStartResult {
  return { ok: false, error: { code, message, stage: 'start', provider: 'github', recoverable: false } };
}

/*** Return a safe, provider-neutral session error. */
function sessionError<T>(message: string): AuthResult<T> {
  return { ok: false, error: { code: 'invalid_session', message } };
}
