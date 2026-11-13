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
export interface GitHubAuthConfig {
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
