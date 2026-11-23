# GitHub App user authorization

This adapter implements the published `@ankhorage/auth` `AuthPort` with GitHub's **confidential web application OAuth flow**.
It supports GitHub App **user access tokens** and their optional rotating refresh tokens.
It does not mint GitHub App installation tokens and it is not a Next.js/React/browser SDK.

Configure a GitHub App's callback URL to match an allowlisted HTTPS URI, and set its read-only repository
**Contents** and **Metadata** permissions only if the consuming app needs repository access.
Organization owners may need to approve/install the app before their repositories are accessible.
The user OAuth flow alone does not grant access to every organization repository.

The host must provide:

- `clientId` and `clientSecret` from a server-side secrets manager.
- `redirectUris` explicitly allowlisted; no arbitrary callback or host-header derivation.
- An `AuthorizationAttemptPersistencePort` from `@ankhorage/auth/persistence` that atomically consumes an
  attempt ID once, bound to the opaque browser session, including on error.
- A `SessionPersistencePort` from `@ankhorage/auth/persistence` that stores encrypted payloads, isolates
  subjects, and atomically rotates or revokes opaque session identifiers.
- A request-scoped `session` binding that reads and writes only an opaque `HttpOnly`, `Secure`, `SameSite`
  cookie identifier. It must never place a GitHub token in that cookie.
- Server-side `payloadEncryption` that seals and opens session and authorization-attempt payloads before
  they reach persistence. The adapter never provides an in-memory or plaintext fallback.
- A confidential server endpoint that calls `startAuthorization` and redirects to the returned GitHub URL.
- A callback endpoint that supplies the attempt ID (from a secure same-site session binding) and full
  callback URL to `completeAuthorization`. The library validates the registered callback and opaque state.
- A server-only consumer of `AuthSession.accessToken` when calling `@ankhorage/repository`.

Token responses must never be serialized to client components. Refresh requests rotate stored credentials;
the host should refresh before expiry and isolate different users. `signOut` clears the local host session,
not all GitHub devices or authorizations. Password login, OTP and password reset are intentionally unsupported.
The `getSession` method returns the host-verified stored session without making API calls on every render;
the host must enforce its own opaque cookie attributes, CSRF protections, request authorization, expiration,
and revocation policies. When GitHub access is revoked, downstream 401s require reauthorization.

Run `bun install`, `bun run build`, `bun run test`, `bun run check-types`,
`bun run lint`, `bun run knip:check` and `bun run format:check` from the repository checkout.
