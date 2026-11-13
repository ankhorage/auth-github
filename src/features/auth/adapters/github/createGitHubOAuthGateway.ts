import type { AuthSession, AuthUser } from '@ankhorage/contracts/auth';

import type { GitHubAuthConfig } from '../../../../types/github.js';

const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const USER_URL = 'https://api.github.com/user';

/*** Bind the confidential GitHub user-token exchange and refresh to a fixed provider endpoint. */
export function createGitHubOAuthGateway(config: GitHubAuthConfig) {
  return {
    exchangeCodeAsync: (code: string, redirectUri: string) =>
      readSessionAsync(config, { code, redirect_uri: redirectUri }),
    refreshTokenAsync: (refreshToken: string, expectedUserId: string) =>
      readSessionAsync(
        config,
        { grant_type: 'refresh_token', refresh_token: refreshToken },
        expectedUserId,
      ),
  };
}

/*** Exchange a GitHub user token and verify that it matches the expected identity when refreshing. */
async function readSessionAsync(
  config: GitHubAuthConfig,
  parameters: Readonly<Record<string, string>>,
  expectedUserId?: string,
): Promise<AuthSession> {
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    ...parameters,
  });
  const response = await (config.fetcher ?? fetch)(TOKEN_URL, {
    method: 'POST',
    redirect: 'error',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
    signal: AbortSignal.timeout(config.requestTimeoutMs ?? 15_000),
  });
  if (!response.ok) throw new Error('GitHub token exchange failed.');
  const value: unknown = await response.json();
  const token = readToken(value);
  const user = await readUserAsync(config, token.accessToken);
  if (expectedUserId !== undefined && user.id !== expectedUserId)
    throw new Error('GitHub identity changed during token refresh.');
  return {
    accessToken: token.accessToken,
    ...(token.refreshToken === undefined ? {} : { refreshToken: token.refreshToken }),
    ...(token.expiresIn === undefined
      ? {}
      : { expiresAt: (config.now ?? Date.now)() + token.expiresIn * 1_000 }),
    tokenType: 'bearer',
    user,
  };
}

/*** Request the authoritative GitHub user for this token rather than trusting account hints. */
async function readUserAsync(config: GitHubAuthConfig, token: string): Promise<AuthUser> {
  const response = await (config.fetcher ?? fetch)(USER_URL, {
    method: 'GET',
    redirect: 'error',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: 'Bearer ' + token,
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: AbortSignal.timeout(config.requestTimeoutMs ?? 15_000),
  });
  if (!response.ok) throw new Error('GitHub identity verification failed.');
  const value: unknown = await response.json();
  if (!isValidGitHubUser(value)) throw new Error('GitHub returned an invalid user identity.');
  return {
    id: String(value.id),
    username: value.login,
    ...(typeof value.name === 'string' && value.name.trim() !== ''
      ? { displayName: value.name }
      : {}),
    ...(typeof value.email === 'string' && value.email.trim() !== '' ? { email: value.email } : {}),
    ...(typeof value.avatar_url === 'string' && value.avatar_url.startsWith('https://')
      ? { avatarUrl: value.avatar_url }
      : {}),
  };
}

/*** Reject non-bearer, malformed, missing or nonexpiring-looking GitHub OAuth responses. */
function readToken(value: unknown): {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresIn?: number;
} {
  if (
    !isRecord(value) ||
    !hasValidAccessToken(value) ||
    !hasValidTokenType(value) ||
    !hasValidRefreshToken(value) ||
    !hasValidTokenExpiration(value)
  )
    throw new Error('GitHub returned an invalid token response.');
  return {
    accessToken: value.access_token,
    ...(typeof value.refresh_token === 'string' ? { refreshToken: value.refresh_token } : {}),
    ...(typeof value.expires_in === 'number' ? { expiresIn: value.expires_in } : {}),
  };
}

/*** Validate the signed-in GitHub account's stable numeric identity and login. */
function isValidGitHubUser(value: unknown): value is GitHubUserRecord {
  return (
    isRecord(value) &&
    typeof value.id === 'number' &&
    Number.isSafeInteger(value.id) &&
    value.id > 0 &&
    typeof value.login === 'string' &&
    value.login.trim() !== ''
  );
}

interface GitHubUserRecord extends Record<string, unknown> {
  id: number;
  login: string;
}

/*** Require a non-empty opaque OAuth access token. */
function hasValidAccessToken(
  value: Record<string, unknown>,
): value is Record<string, unknown> & { access_token: string } {
  return typeof value.access_token === 'string' && value.access_token.length > 0;
}

/*** Only accept a bearer token when GitHub states a token type. */
function hasValidTokenType(value: Record<string, unknown>): boolean {
  return (
    value.token_type === undefined ||
    (typeof value.token_type === 'string' && value.token_type.toLowerCase() === 'bearer')
  );
}

/*** Reject refresh credentials of unexpected provider data types. */
function hasValidRefreshToken(value: Record<string, unknown>): boolean {
  return (
    value.refresh_token === undefined ||
    (typeof value.refresh_token === 'string' && value.refresh_token.length > 0)
  );
}

/*** Accept optional positive integer GitHub access-token lifetimes. */
function hasValidTokenExpiration(value: Record<string, unknown>): boolean {
  return (
    value.expires_in === undefined ||
    (typeof value.expires_in === 'number' &&
      Number.isSafeInteger(value.expires_in) &&
      value.expires_in > 0)
  );
}

/*** Narrow untrusted provider JSON before inspecting its fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
