# Public API

## createGitHubAuthAdapter

Kind: `function`
Module: `src/features/auth/adapters/github/createGitHubAuthAdapter.ts`
Source: `src/features/auth/adapters/github/createGitHubAuthAdapter.ts:9:1`

Implement the published AuthPort with GitHub OAuth and explicitly unsupported credentials operations.

### Signatures

- `(config: GitHubAuthConfig) => AuthPort`
  - config: `GitHubAuthConfig`
  - returns: `AuthPort`

## GitHubAppAuthConfig

Kind: `type`
Module: `src/types/github.ts`
Source: `src/types/github.ts:39:1`

Configure the GitHub App user-authorization flow and its only supported renewal scope.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| authorizationAttempts | property | `AuthorizationAttemptPersistencePort` | yes |  |
| authorizationAttemptTtlMs | property | `number \| undefined` | no |  |
| authorizationMode | property | `"github-app"` | yes |  |
| clientId | property | `string` | yes |  |
| clientSecret | property | `string` | yes |  |
| createAttemptId | property | `(() => string) \| undefined` | no |  |
| createSessionId | property | `(() => string) \| undefined` | no |  |
| createState | property | `(() => string) \| undefined` | no |  |
| fetcher | property | `typeof fetch \| undefined` | no |  |
| now | property | `(() => number) \| undefined` | no |  |
| payloadEncryption | property | `GitHubPayloadEncryption` | yes |  |
| redirectUris | property | `readonly string[]` | yes |  |
| requestTimeoutMs | property | `number \| undefined` | no |  |
| session | property | `GitHubSessionBinding` | yes |  |
| sessions | property | `SessionPersistencePort` | yes |  |

## GitHubAuthConfig

Kind: `unknown`
Module: `src/types/github.ts`
Source: `src/types/github.ts:49:1`

Select one explicit GitHub authorization protocol; hosts must not infer it from credentials.

## GitHubOAuthAppConfig

Kind: `type`
Module: `src/types/github.ts`
Source: `src/types/github.ts:44:1`

Configure a classic GitHub OAuth App with the minimum login scope and optional repository scope.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| authorizationAttempts | property | `AuthorizationAttemptPersistencePort` | yes |  |
| authorizationAttemptTtlMs | property | `number \| undefined` | no |  |
| authorizationMode | property | `"oauth-app"` | yes |  |
| clientId | property | `string` | yes |  |
| clientSecret | property | `string` | yes |  |
| createAttemptId | property | `(() => string) \| undefined` | no |  |
| createSessionId | property | `(() => string) \| undefined` | no |  |
| createState | property | `(() => string) \| undefined` | no |  |
| fetcher | property | `typeof fetch \| undefined` | no |  |
| now | property | `(() => number) \| undefined` | no |  |
| payloadEncryption | property | `GitHubPayloadEncryption` | yes |  |
| redirectUris | property | `readonly string[]` | yes |  |
| requestTimeoutMs | property | `number \| undefined` | no |  |
| session | property | `GitHubSessionBinding` | yes |  |
| sessions | property | `SessionPersistencePort` | yes |  |

## GitHubPayloadEncryption

Kind: `type`
Module: `src/types/github.ts`
Source: `src/types/github.ts:15:1`

Encrypt and decrypt adapter payloads at the server boundary without exposing plaintext storage.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| decrypt | method | `(payload: EncryptedPayload) => Promise<unknown>` | yes |  |
| encrypt | method | `(payload: unknown) => Promise<EncryptedPayload>` | yes |  |

## GitHubSessionBinding

Kind: `type`
Module: `src/types/github.ts`
Source: `src/types/github.ts:8:1`

Bind the adapter to one opaque, HttpOnly host session and allow only safe identifier replacement.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| clearSessionId | method | `() => Promise<void>` | yes |  |
| replaceSessionId | method | `(sessionId: string) => Promise<void>` | yes |  |
| sessionId | property | `string` | yes |  |
