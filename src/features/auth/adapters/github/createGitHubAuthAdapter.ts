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
  if (
    !config.clientId.trim() ||
    !config.clientSecret.trim() ||
    config.redirectUris.length === 0 ||
    !isOptionalPositiveInteger(config.authorizationAttemptTtlMs) ||
    !isOptionalPositiveInteger(config.requestTimeoutMs)
  )
    throw new Error('Invalid GitHub App authorization configuration.');
  if (!config.redirectUris.every(isSecureRedirectUri))
    throw new Error('GitHub OAuth callback URLs must be explicitly allowlisted HTTPS URLs.');
}

/*** Validate an optional positive integer without bloating the adapter configuration policy. */
function isOptionalPositiveInteger(value: number | undefined): boolean {
  return value === undefined || (Number.isSafeInteger(value) && value > 0);
}

/*** Require exact canonical HTTPS callback URIs without embedded credentials or query data. */
function isSecureRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      url.toString() === value
    );
  } catch {
    return false;
  }
}

/*** Make unsupported provider operations fail closed rather than simulate successful auth. */
function unsupported<T>(): AuthResult<T> {
  return {
    ok: false,
    error: { code: 'unsupported_operation', message: 'GitHub uses browser authorization.' },
  };
}
