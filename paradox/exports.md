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
Source: `src/types/github.ts:41:1`

Configure the GitHub App user-authorization flow and its only supported renewal scope.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| authorizationAttempts | property | `GitHubAuthorizationAttemptStore` | yes |  |
| authorizationAttemptTtlMs | property | `number \| undefined` | no |  |
| authorizationMode | property | `"github-app"` | yes |  |
| clientId | property | `string` | yes |  |
| clientSecret | property | `string` | yes |  |
| createAttemptId | property | `(() => string) \| undefined` | no |  |
| createState | property | `(() => string) \| undefined` | no |  |
| fetcher | property | `typeof fetch \| undefined` | no |  |
| now | property | `(() => number) \| undefined` | no |  |
| redirectUris | property | `readonly string[]` | yes |  |
| requestTimeoutMs | property | `number \| undefined` | no |  |
| sessions | property | `GitHubSessionStore` | yes |  |

## GitHubAuthConfig

Kind: `unknown`
Module: `src/types/github.ts`
Source: `src/types/github.ts:51:1`

Select one explicit GitHub authorization protocol; hosts must not infer it from credentials.

## GitHubAuthorizationAttempt

Kind: `type`
Module: `src/types/github.ts`
Source: `src/types/github.ts:4:1`

One short-lived GitHub authorization bound to a host-managed browser session.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| attemptId | property | `string` | yes |  |
| expiresAt | property | `number` | yes |  |
| redirectUri | property | `string` | yes |  |
| state | property | `string` | yes |  |

## GitHubAuthorizationAttemptStore

Kind: `type`
Module: `src/types/github.ts`
Source: `src/types/github.ts:12:1`

Durable attempt storage; consume must atomically delete before returning.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| consume | method | `(attemptId: string, now: number) => Promise<GitHubAuthorizationAttempt \| null>` | yes |  |
| create | method | `(attempt: GitHubAuthorizationAttempt) => Promise<void>` | yes |  |
| purgeExpired | method | `(now: number) => Promise<void>` | yes |  |

## GitHubOAuthAppConfig

Kind: `type`
Module: `src/types/github.ts`
Source: `src/types/github.ts:46:1`

Configure a classic GitHub OAuth App with the minimum login scope and optional repository scope.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| authorizationAttempts | property | `GitHubAuthorizationAttemptStore` | yes |  |
| authorizationAttemptTtlMs | property | `number \| undefined` | no |  |
| authorizationMode | property | `"oauth-app"` | yes |  |
| clientId | property | `string` | yes |  |
| clientSecret | property | `string` | yes |  |
| createAttemptId | property | `(() => string) \| undefined` | no |  |
| createState | property | `(() => string) \| undefined` | no |  |
| fetcher | property | `typeof fetch \| undefined` | no |  |
| now | property | `(() => number) \| undefined` | no |  |
| redirectUris | property | `readonly string[]` | yes |  |
| requestTimeoutMs | property | `number \| undefined` | no |  |
| sessions | property | `GitHubSessionStore` | yes |  |

## GitHubSessionStore

Kind: `type`
Module: `src/types/github.ts`
Source: `src/types/github.ts:19:1`

Request-scoped server session persistence; never a shared global user slot.

### Members

| Name | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| clear | method | `() => Promise<void>` | yes |  |
| get | method | `() => Promise<AuthSession \| null>` | yes |  |
| save | method | `(session: AuthSession) => Promise<void>` | yes |  |
