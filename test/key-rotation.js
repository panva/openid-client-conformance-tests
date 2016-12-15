'use strict';

const {
  register,
  noFollow,
  redirect_uri,
  describe,
  authorize,
  authorizationCallback,
  it,
} = require('./helper');

const assert = require('assert');
const timekeeper = require('timekeeper');

afterEach(timekeeper.reset);

describe('Key Rotation', function () {
  it('rp-key-rotation-op-sign-key @code-config,@code-dynamic', async function () {
    const { client } = await register('rp-key-rotation-op-sign-key', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    await authorizationCallback(client, redirect_uri, params);

    timekeeper.travel(Date.now() + (61 * 1000)); // travel one minute from now, making the cached keystore stale

    const secondAuthorization = await authorize(client.authorizationUrl({ redirect_uri }), noFollow);
    const secondParams = client.callbackParams(secondAuthorization.headers.location);
    const tokens = await authorizationCallback(client, redirect_uri, secondParams);
    assert(tokens);
  });

  it('rp-key-rotation-op-enc-key');
});
