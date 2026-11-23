import type { AuthPort } from '@ankhorage/auth';
import type { DurableSession } from '@ankhorage/auth/persistence';
import type { AuthResult, AuthSession, SignOutInput } from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig } from '../../../../types/github.js';
import { createGitHubOAuthGateway } from './createGitHubOAuthGateway.js';

/*** Bind session-related AuthPort operations to a request-scoped durable host store. */
export function createGitHubSessionOperations(
  config: GitHubAuthConfig,
): Pick<AuthPort, 'signOut' | 'getSession' | 'refreshSession'> {
  const gateway = createGitHubOAuthGateway(config);
  return {
    signOut: (input) => signOutAsync(config, input),
    getSession: () => getSessionAsync(config),
    refreshSession: () => refreshSessionAsync(config, gateway),
  };
}

/*** Remove only the host's local session; never claim global GitHub sign-out. */
async function signOutAsync(config: GitHubAuthConfig, input?: SignOutInput): Promise<AuthResult> {
  if (input?.allDevices)
    return {
      ok: false,
      error: { code: 'unsupported_operation', message: 'Global sign-out is not supported.' },
    };
  try {
    const current = await config.sessions.read(
      config.session.sessionId,
      (config.now ?? Date.now)(),
    );
    if (current.status === 'unavailable') return sessionError('Unable to end the local session.');
    if (current.status === 'found') {
      const result = await config.sessions.revoke({
        sessionId: config.session.sessionId,
        subject: current.session.subject,
        now: (config.now ?? Date.now)(),
      });
      if (result.status !== 'revoked' && result.status !== 'already_revoked')
        return sessionError('Unable to end the local session.');
    }
    await config.session.clearSessionId();
    return { ok: true };
  } catch {
    return sessionError('Unable to end the local session.');
  }
}

/*** Read the stored session without silently treating expired tokens as authenticated. */
async function getSessionAsync(config: GitHubAuthConfig): Promise<AuthResult<AuthSession | null>> {
  try {
    const stored = await readStoredSessionAsync(config);
    return stored === null ? { ok: true, data: null } : { ok: true, data: stored.session };
  } catch {
    return sessionError('Unable to read the local session.');
  }
}

/*** Refresh a token and fail closed if GitHub returns another user identity. */
async function refreshSessionAsync(
  config: GitHubAuthConfig,
  gateway: ReturnType<typeof createGitHubOAuthGateway>,
): Promise<AuthResult<AuthSession | null>> {
  try {
    const stored = await readStoredSessionAsync(config);
    if (stored === null) return { ok: true, data: null };
    const { session } = stored;
    if (!session.refreshToken) {
      return session.expiresAt === undefined || session.expiresAt > (config.now ?? Date.now)()
        ? { ok: true, data: session }
        : sessionError('GitHub authorization has expired.');
    }
    const refreshed = await gateway.refreshTokenAsync(session.refreshToken, session.user.id);
    const sessionId = createOpaqueValue(config.createSessionId);
    const now = (config.now ?? Date.now)();
    const result = await config.sessions.rotate({
      replacedSessionId: stored.durableSession.sessionId,
      replacement: {
        sessionId,
        subject: stored.durableSession.subject,
        encryptedPayload: await config.payloadEncryption.encrypt(refreshed),
        createdAt: now,
        expiresAt: refreshed.expiresAt ?? MAX_DATE_MS,
      },
      subject: stored.durableSession.subject,
      now,
    });
    if (result.status !== 'rotated') return sessionError('GitHub session refresh failed.');
    await config.session.replaceSessionId(sessionId);
    return { ok: true, data: refreshed };
  } catch {
    return sessionError('GitHub session refresh failed.');
  }
}

const MAX_DATE_MS = 8_640_000_000_000_000;

/*** Read and decrypt only a currently valid session whose payload identity matches its durable owner. */
async function readStoredSessionAsync(
  config: GitHubAuthConfig,
): Promise<{ readonly session: AuthSession; readonly durableSession: DurableSession } | null> {
  const result = await config.sessions.read(config.session.sessionId, (config.now ?? Date.now)());
  if (result.status === 'not_found' || result.status === 'revoked' || result.status === 'expired')
    return null;
  if (result.status !== 'found') throw new Error('Session persistence unavailable.');
  const session = await config.payloadEncryption.decrypt(result.session.encryptedPayload);
  if (!isAuthSession(session) || session.user.id !== result.session.subject.userId)
    throw new Error('Invalid encrypted session payload.');
  return { session, durableSession: result.session };
}

/*** Generate a host-overridable opaque session identifier without retaining it in process memory. */
function createOpaqueValue(factory: (() => string) | undefined): string {
  return factory?.() ?? crypto.randomUUID();
}

/*** Verify decrypted storage data before it can authorize a GitHub user or refresh credential. */
function isAuthSession(value: unknown): value is AuthSession {
  return (
    isRecord(value) &&
    typeof value.accessToken === 'string' &&
    value.accessToken.length > 0 &&
    isRecord(value.user) &&
    typeof value.user.id === 'string' &&
    value.user.id.length > 0
  );
}

/*** Narrow untrusted decrypted data without accepting arrays or null as session records. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/*** Normalize session failures without exposing secrets from storage or GitHub. */
function sessionError<T>(message: string): AuthResult<T> {
  return { ok: false, error: { code: 'invalid_session', message } };
}
