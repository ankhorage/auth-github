import type {
  AuthorizationAttemptPersistencePort,
  EncryptedPayload,
  SessionPersistencePort,
} from '@ankhorage/auth/persistence';

/*** Bind the adapter to one opaque, HttpOnly host session and allow only safe identifier replacement. */
export interface GitHubSessionBinding {
  readonly sessionId: string;
  replaceSessionId(sessionId: string): Promise<void>;
  clearSessionId(): Promise<void>;
}

/*** Encrypt and decrypt adapter payloads at the server boundary without exposing plaintext storage. */
export interface GitHubPayloadEncryption {
  encrypt(payload: unknown): Promise<EncryptedPayload>;
  decrypt(payload: EncryptedPayload): Promise<unknown>;
}

/*** Host-supplied confidential GitHub App configuration and independently scoped persistence. */
interface GitHubAuthConfigBase {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUris: readonly string[];
  readonly authorizationAttempts: AuthorizationAttemptPersistencePort;
  readonly sessions: SessionPersistencePort;
  readonly session: GitHubSessionBinding;
  readonly payloadEncryption: GitHubPayloadEncryption;
  readonly fetcher?: typeof fetch;
  readonly now?: () => number;
  readonly createAttemptId?: () => string;
  readonly createSessionId?: () => string;
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
