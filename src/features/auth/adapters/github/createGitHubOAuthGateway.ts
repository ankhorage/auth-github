import type { AuthSession, AuthUser } from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig } from '../../../../types/github.js';

const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const USER_URL = 'https://api.github.com/user';

/*** Create the narrowly scoped GitHub network edge for user-token exchange and refresh. */
export function createGitHubOAuthGateway(config: GitHubAuthConfig) {
  const fetcher = config.fetcher ?? fetch;
  const now = config.now ?? Date.now;
  const timeoutMs = config.requestTimeoutMs ?? 15_000;

  return {
    exchangeCodeAsync: async (code: string, redirectUri: string) =>
      readSessionAsync({ code, redirect_uri: redirectUri }, undefined),
    refreshTokenAsync: async (refreshToken: string, expectedUserId: string) =>
      readSessionAsync(
        { grant_type: 'refresh_token', refresh_token: refreshToken },
        expectedUserId
      ),
  };

  /*** Exchange a confidential GitHub code or refresh token, then resolve its verified identity. */
  async function readSessionAsync(
    parameters: Readonly<Record<string, string>>,
    expectedUserId: string | undefined
  ): Promise<AuthSession> {
    const body = new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      ...parameters,
    });
    const response = await fetcher(TOKEN_URL, {
      method: 'POST',
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new Error('GitHub token exchange failed.');
    const value: unknown = await response.json();
    const token = readToken(value);
    const user = await readUserAsync(token.accessToken);
    if (expectedUserId !== undefined && user.id !== expectedUserId)
      throw new Error('GitHub identity changed during token refresh.');
    return {
      accessToken: token.accessToken,
      ...(token.refreshToken === undefined ? {} : { refreshToken: token.refreshToken }),
      ...(token.expiresIn === undefined
        ? {}
        : { expiresAt: now() + token.expiresIn * 1_000 }),
      tokenType: token.tokenType,
      user,
    };
  }

  /*** Validate GitHub's bearer token by requesting its authoritative user identity. */
  async function readUserAsync(token: string): Promise<AuthUser> {
    const response = await fetcher(USER_URL, {
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: 'Bearer ' + token,
        'X-GitHub-Api-Version': '2022-11-28',
      },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new Error('GitHub identity verification failed.');
    const value: unknown = await response.json();
    if (!isRecord(value) || !Number.isSafeInteger(value.id) || typeof value.id !== 'number' ||
        value.id < 1 || typeof value.login !== 'string' || value.login.trim() === '')
      throw new Error('GitHub returned an invalid user identity.');
    return {
      id: String(value.id),
      username: value.login,
      ...(typeof value.name === 'string' && value.name.trim() !== ''
        ? { displayName: value.name } : {}),
      ...(typeof value.email === 'string' && value.email.trim() !== ''
        ? { email: value.email } : {}),
      ...(typeof value.avatar_url === 'string' && value.avatar_url.startsWith('https://')
        ? { avatarUrl: value.avatar_url } : {}),
    };
  }
}

/*** Require a nonempty, bearer-compatible GitHub OAuth token response. */
function readToken(value: unknown): {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresIn?: number;
  readonly tokenType: string;
} {
  if (!isRecord(value) || typeof value.access_token !== 'string' ||
      value.access_token.length === 0 || (value.token_type !== undefined &&
      String(value.token_type).toLowerCase() !== 'bearer') ||
      (value.refresh_token !== undefined &&
      (typeof value.refresh_token !== 'string' || value.refresh_token.length === 0)) ||
      (value.expires_in !== undefined &&
      (typeof value.expires_in !== 'number' || !Number.isSafeInteger(value.expires_in) ||
      value.expires_in < 1))) {
    throw new Error('GitHub returned an invalid token response.');
  }
  return {
    accessToken: value.access_token,
    ...(typeof value.refresh_token === 'string' ? { refreshToken: value.refresh_token } : {}),
    ...(typeof value.expires_in === 'number' ? { expiresIn: value.expires_in } : {}),
    tokenType: 'bearer',
  };
}

/*** Narrow provider JSON without trusting prototype or array-like input. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
