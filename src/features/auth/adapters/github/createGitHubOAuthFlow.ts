import type { AuthPort } from '@ankhorage/auth';
import type { DurableSession } from '@ankhorage/auth/persistence';
import type {
  AuthOAuthCompletionResult,
  AuthOAuthError,
  AuthOAuthStartResult,
  AuthSession,
  CompleteOAuthAuthorizationInput,
  StartOAuthAuthorizationInput,
} from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig } from '../../../../types/github.js';
import { createGitHubOAuthGateway } from './createGitHubOAuthGateway.js';

const DEFAULT_TTL_MS = 600_000;
const MAX_DATE_MS = 8_640_000_000_000_000;

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
    !hasSupportedScopes(config, input.scopes) ||
    (input.queryParams !== undefined && Object.keys(input.queryParams).length > 0)
  )
    return oauthStartError(
      'authorization_failed',
      'Unsupported GitHub App authorization parameters.',
    );

  const now = (config.now ?? Date.now)();
  const attempt = {
    attemptId: createOpaqueValue(config.createAttemptId),
    state: createOpaqueValue(config.createState),
    redirectUri: input.redirectUri,
  };
  try {
    const result = await config.authorizationAttempts.create({
      attemptId: attempt.attemptId,
      sessionId: config.session.sessionId,
      encryptedPayload: await config.payloadEncryption.encrypt(attempt),
      expiresAt: now + (config.authorizationAttemptTtlMs ?? DEFAULT_TTL_MS),
    });
    if (result.status !== 'created')
      return oauthStartError('authorization_failed', 'Unable to start GitHub authorization.');
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

/*** Generate host-overridable opaque OAuth values without detaching the platform Crypto receiver. */
function createOpaqueValue(factory: (() => string) | undefined): string {
  return factory?.() ?? crypto.randomUUID();
}

/*** Restrict each GitHub authorization protocol to its documented, least-privilege scope vocabulary. */
function hasSupportedScopes(
  config: GitHubAuthConfig,
  scopes: readonly string[] | undefined,
): boolean {
  const permittedScopes =
    config.authorizationMode === 'oauth-app' ? ['read:user', 'repo'] : ['offline_access'];
  if (scopes === undefined) return config.authorizationMode === 'github-app';
  const uniqueScopes = new Set(scopes);
  return (
    uniqueScopes.size === scopes.length &&
    scopes.every((scope) => permittedScopes.includes(scope)) &&
    (config.authorizationMode === 'github-app' || uniqueScopes.has('read:user'))
  );
}

/*** Construct GitHub's fixed OAuth endpoint without accepting arbitrary caller query parameters. */
function createAuthorizationUrl(
  clientId: string,
  attempt: { readonly state: string; readonly redirectUri: string },
  scopes: readonly string[] | undefined,
): string {
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', attempt.redirectUri);
  url.searchParams.set('state', attempt.state);
  if (scopes && scopes.length > 0) url.searchParams.set('scope', scopes.join(' '));
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
      const sessionId = await persistSessionAsync(config, session);
      if (sessionId === null) return oauthError('session_persistence_failed', 'session');
      await config.session.replaceSessionId(sessionId);
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
): Promise<{
  readonly attemptId: string;
  readonly state: string;
  readonly redirectUri: string;
} | null> {
  try {
    const result = await config.authorizationAttempts.consume({
      attemptId,
      sessionId: config.session.sessionId,
      now: (config.now ?? Date.now)(),
    });
    if (result.status !== 'consumed') return null;
    const payload = await config.payloadEncryption.decrypt(result.attempt.encryptedPayload);
    return isAttemptPayload(payload, attemptId) ? payload : null;
  } catch {
    return null;
  }
}

/*** Create or atomically rotate a verified user's opaque durable session before binding it to the browser. */
async function persistSessionAsync(
  config: GitHubAuthConfig,
  session: AuthSession,
): Promise<string | null> {
  const now = (config.now ?? Date.now)();
  const sessionId = createOpaqueValue(config.createSessionId);
  const durableSession: DurableSession = {
    sessionId,
    subject: { userId: session.user.id },
    encryptedPayload: await config.payloadEncryption.encrypt(session),
    createdAt: now,
    expiresAt: session.expiresAt ?? MAX_DATE_MS,
  };
  const current = await config.sessions.read(config.session.sessionId, now);
  if (current.status === 'found') {
    if (current.session.subject.userId !== session.user.id) return null;
    const result = await config.sessions.rotate({
      replacedSessionId: current.session.sessionId,
      replacement: durableSession,
      subject: current.session.subject,
      now,
    });
    return result.status === 'rotated' ? sessionId : null;
  }
  if (current.status === 'unavailable') return null;
  const result = await config.sessions.create(durableSession);
  return result.status === 'created' ? sessionId : null;
}

/*** Reject decrypted attempt payloads that are malformed or no longer match the consumed record. */
function isAttemptPayload(
  value: unknown,
  attemptId: string,
): value is { readonly attemptId: string; readonly state: string; readonly redirectUri: string } {
  return (
    isRecord(value) &&
    value.attemptId === attemptId &&
    typeof value.state === 'string' &&
    value.state.length > 0 &&
    typeof value.redirectUri === 'string'
  );
}

/*** Narrow encrypted host payloads before reading their OAuth fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
