import { expect, test } from 'bun:test';

import {
  createCallback,
  createFixture,
  startAuthorizationAsync,
} from './createGitHubAuthAdapter.fixture.js';

test('consumes a callback bound to another opaque browser session without exchanging its code', async () => {
  const fixture = createFixture();
  await startAuthorizationAsync(fixture);
  fixture.state.sessionId = 'another_browser_session';
  expect(await fixture.adapter.completeAuthorization(createCallback())).toMatchObject({
    ok: false,
    error: { code: 'authorization_attempt_not_found' },
  });
  expect(fixture.attempts.size).toBe(0);
  expect(fixture.state.tokenCalls).toHaveLength(0);
});

test('rotates a same-user session during renewed authorization without leaving two identifiers valid', async () => {
  const fixture = createFixture();
  await startAuthorizationAsync(fixture);
  await fixture.adapter.completeAuthorization(createCallback());
  const firstSessionId = fixture.state.sessionId;
  await startAuthorizationAsync(fixture);
  await fixture.adapter.completeAuthorization(createCallback());
  expect(fixture.state.sessionId).not.toBe(firstSessionId);
  expect(fixture.sessions.has(firstSessionId)).toBe(false);
});

test('revokes the local session while rejecting unsupported credential and global sign-out operations', async () => {
  const fixture = createFixture();
  expect(
    await fixture.adapter.signIn({ identifier: { kind: 'username', value: 'u' } }),
  ).toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(
    await fixture.adapter.signUp({ identifier: { kind: 'email', value: 'a@example.com' } }),
  ).toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(
    await fixture.adapter.requestPasswordReset({
      identifier: { kind: 'email', value: 'a@example.com' },
    }),
  ).toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  expect(
    await fixture.adapter.verifyOtp({
      identifier: { kind: 'email', value: 'a@example.com' },
      token: 'x',
    }),
  ).toMatchObject({ ok: false, error: { code: 'unsupported_operation' } });
  fixture.setSession({ accessToken: 'token_1', user: { id: '42' } });
  expect(await fixture.adapter.signOut({ allDevices: true })).toMatchObject({
    ok: false,
    error: { code: 'unsupported_operation' },
  });
  expect(fixture.state.session).not.toBeNull();
  expect(await fixture.adapter.signOut()).toEqual({ ok: true });
  expect(fixture.state.session).toBeNull();
  expect(fixture.state.sessionId).toBe('');
});
