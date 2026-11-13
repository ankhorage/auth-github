import type { AuthPort } from '@ankhorage/auth';
import type {
  AuthOAuthCompletionResult,
  AuthOAuthError,
  AuthOAuthStartResult,
  CompleteOAuthAuthorizationInput,
  StartOAuthAuthorizationInput,
} from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig, GitHubAuthorizationAttempt } from '../../../../types/github.js';
import { createGitHubOAuthGateway } from './createGitHubOAuthGateway.js';

const DEFAULT_TTL_MS = 600_000;

/*** Provide OAuth start/completion using durable one-use attempts and verified GitHub identity. */
export function createGitHubOAuthFlow(
  config: GitHubAuthConfig,
): Pick<AuthPort, 'startAuthorization' | 'completeAuthorization'> {
  return {
    startAuthorization: (input) => startAuthorizationAsync(config, input),
    completeAuthorization: (input) => completeAuthorizationAsync(config, input),
  };
}

/*** Verify the provider, callback, and requested permissions before storing a new attempt. */
async function startAuthorizationAsync(
  config: GitHubAuthConfig,
  input: StartOAuthAuthorizationInput,
): Promise<AuthOAuthStartResult> {
  if (input.provider !== 'github')
    return oauthStartError('provider_disabled', 'GitHub is the only supported provider.');
  if (!config.redirectUris.includes(input.redirectUri))
    return oauthStartError('invalid_redirect_uri', 'The callback URL is not allowlisted.');
  if (
    input.scopes?.some((scope) => scope !== 'offline_access') ||
    (input.queryParams !== undefined && Object.keys(input.queryParams).length > 0)
  )
    return oauthStartError(
      'authorization_failed',
      'Unsupported GitHub App authorization parameters.',
    );

  const attempt: GitHubAuthorizationAttempt = {
    attemptId: (config.createAttemptId ?? crypto.randomUUID)(),
    state: (config.createState ?? crypto.randomUUID)(),
    redirectUri: input.redirectUri,
    expiresAt: (config.now ?? Date.now)() + (config.authorizationAttemptTtlMs ?? DEFAULT_TTL_MS),
  };
  try {
    await config.authorizationAttempts.purgeExpired((config.now ?? Date.now)());
    await config.authorizationAttempts.create(attempt);
    return {
      ok: true,
      data: {
        attemptId: attempt.attemptId,
        provider: 'github',
        redirectUri: attempt.redirectUri,
        authorizationUrl: createAuthorizationUrl(config.clientId, attempt, input.scopes),
      },
    };
  } catch {
    return oauthStartError('authorization_failed', 'Unable to start GitHub authorization.');
  }
}

/*** Construct GitHub's fixed OAuth endpoint without accepting arbitrary caller query parameters. */
function createAuthorizationUrl(
  clientId: string,
  attempt: GitHubAuthorizationAttempt,
  scopes: readonly string[] | undefined,
): string {
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', attempt.redirectUri);
  url.searchParams.set('state', attempt.state);
  if (scopes?.includes('offline_access')) url.searchParams.set('scope', 'offline_access');
  return url.toString();
}

/*** Consume the OAuth attempt before validation and persist only verified GitHub sessions. */
async function completeAuthorizationAsync(
  config: GitHubAuthConfig,
  input: CompleteOAuthAuthorizationInput,
): Promise<AuthOAuthCompletionResult> {
  const attempt = await consumeAttemptAsync(config, input.attemptId);
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
    const gateway = createGitHubOAuthGateway(config);
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
}

/*** Retire the pending authorization even when storage fails or the attempt is expired. */
async function consumeAttemptAsync(
  config: GitHubAuthConfig,
  attemptId: string,
): Promise<GitHubAuthorizationAttempt | null> {
  try {
    return await config.authorizationAttempts.consume(attemptId, (config.now ?? Date.now)());
  } catch {
    return null;
  }
}

/*** Bind a callback to its configured HTTPS origin/path and a single OAuth state value. */
function parseCallback(
  urlText: string,
  redirectUri: string,
): { readonly state: string; readonly code?: string; readonly error?: string } | null {
  try {
    const actual = new URL(urlText);
    const expected = new URL(redirectUri);
    if (
      actual.origin !== expected.origin ||
      actual.pathname !== expected.pathname ||
      actual.hash !== '' ||
      actual.searchParams.getAll('state').length !== 1 ||
      actual.searchParams.getAll('code').length > 1 ||
      actual.searchParams.getAll('error').length > 1
    )
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

/*** Return contract-compatible OAuth failures without raw codes, tokens, or provider payloads. */
function oauthError(
  code: AuthOAuthError['code'],
  stage: AuthOAuthError['stage'],
): AuthOAuthCompletionResult {
  return {
    ok: false,
    status: 'error',
    error: {
      code,
      stage,
      provider: 'github',
      recoverable: false,
      message: 'GitHub authorization failed.',
    },
  };
}

/*** Refuse incorrect provider setup with a portable, nonsecret OAuth start result. */
function oauthStartError(code: AuthOAuthError['code'], message: string): AuthOAuthStartResult {
  return {
    ok: false,
    error: {
      code,
      message,
      stage: 'start',
      provider: 'github',
      recoverable: false,
    },
  };
}
