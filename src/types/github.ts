import type { AuthSession } from '@ankhorage/contracts/auth';

/*** One short-lived GitHub authorization bound to a host-managed browser session. */
export interface GitHubAuthorizationAttempt {
  readonly attemptId: string;
  readonly state: string;
  readonly redirectUri: string;
  readonly expiresAt: number;
}

/*** Durable attempt storage; consume must atomically delete before returning. */
export interface GitHubAuthorizationAttemptStore {
  create(attempt: GitHubAuthorizationAttempt): Promise<void>;
  consume(attemptId: string, now: number): Promise<GitHubAuthorizationAttempt | null>;
  purgeExpired(now: number): Promise<void>;
}

/*** Request-scoped server session persistence; never a shared global user slot. */
export interface GitHubSessionStore {
  get(): Promise<AuthSession | null>;
  save(session: AuthSession): Promise<void>;
  clear(): Promise<void>;
}

/*** Host-supplied confidential GitHub App configuration and independently scoped persistence. */
interface GitHubAuthConfigBase {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUris: readonly string[];
  readonly authorizationAttempts: GitHubAuthorizationAttemptStore;
  readonly sessions: GitHubSessionStore;
  readonly fetcher?: typeof fetch;
  readonly now?: () => number;
  readonly createAttemptId?: () => string;
  readonly createState?: () => string;
  readonly authorizationAttemptTtlMs?: number;
  readonly requestTimeoutMs?: number;
}

/*** Configure the GitHub App user-authorization flow and its only supported renewal scope. */
export interface GitHubAppAuthConfig extends GitHubAuthConfigBase {
  readonly authorizationMode: 'github-app';
}

/*** Configure a classic GitHub OAuth App with the minimum login scope and optional repository scope. */
export interface GitHubOAuthAppConfig extends GitHubAuthConfigBase {
  readonly authorizationMode: 'oauth-app';
}

/*** Select one explicit GitHub authorization protocol; hosts must not infer it from credentials. */
export type GitHubAuthConfig = GitHubAppAuthConfig | GitHubOAuthAppConfig;
