import type { AuthPort } from '@ankhorage/auth';
import type { AuthResult, AuthSession, AuthUser } from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig } from '../../../../types/github.js';
import { createGitHubOAuthFlow } from './createGitHubOAuthFlow.js';
import { createGitHubSessionOperations } from './createGitHubSessionOperations.js';

/*** Implement the published AuthPort with GitHub OAuth and explicitly unsupported credentials operations. */
export function createGitHubAuthAdapter(config: GitHubAuthConfig): AuthPort {
  validateConfig(config);
  return {
    ...createGitHubSessionOperations(config),
    ...createGitHubOAuthFlow(config),
    signIn: () => Promise.resolve(unsupported<AuthSession>()),
    signUp: () => Promise.resolve(unsupported<AuthSession | AuthUser>()),
    requestPasswordReset: () => Promise.resolve(unsupported<void>()),
    verifyOtp: () => Promise.resolve(unsupported<AuthSession>()),
  };
}

/*** Refuse configuration with secrets missing or callbacks that cannot be trusted. */
function validateConfig(config: GitHubAuthConfig): void {
  if (!config.clientId.trim() || !config.clientSecret.trim() || config.redirectUris.length === 0 ||
      (config.authorizationAttemptTtlMs !== undefined &&
        (!Number.isSafeInteger(config.authorizationAttemptTtlMs) ||
        config.authorizationAttemptTtlMs < 1)) ||
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

/*** Make unsupported provider operations fail closed rather than simulate successful auth. */
function unsupported<T>(): AuthResult<T> {
  return {
    ok: false,
    error: { code: 'unsupported_operation', message: 'GitHub uses browser authorization.' },
  };
}
