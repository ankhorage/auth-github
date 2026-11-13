import type { AuthPort } from '@ankhorage/auth';
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
    await config.sessions.clear();
    return { ok: true };
  } catch {
    return sessionError('Unable to end the local session.');
  }
}

/*** Read the stored session without silently treating expired tokens as authenticated. */
async function getSessionAsync(config: GitHubAuthConfig): Promise<AuthResult<AuthSession | null>> {
  try {
    const session = await config.sessions.get();
    const expired =
      session?.expiresAt !== undefined && session.expiresAt <= (config.now ?? Date.now)();
    return { ok: true, data: expired ? null : session };
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
    const session = await config.sessions.get();
    if (session === null) return { ok: true, data: null };
    if (!session.refreshToken) {
      return session.expiresAt === undefined || session.expiresAt > (config.now ?? Date.now)()
        ? { ok: true, data: session }
        : sessionError('GitHub authorization has expired.');
    }
    const refreshed = await gateway.refreshTokenAsync(session.refreshToken, session.user.id);
    await config.sessions.save(refreshed);
    return { ok: true, data: refreshed };
  } catch {
    return sessionError('GitHub session refresh failed.');
  }
}

/*** Normalize session failures without exposing secrets from storage or GitHub. */
function sessionError<T>(message: string): AuthResult<T> {
  return { ok: false, error: { code: 'invalid_session', message } };
}
