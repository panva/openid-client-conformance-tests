'use strict';

const {
  register,
  noFollow,
  redirect_uri,
} = require('./helper');

const got = require('got');
const timekeeper = require('timekeeper');

afterEach(timekeeper.reset);

describe('Key Rotation', function () {
  it('rp-key-rotation-op-sign-key @config,@dynamic', async function () {
    const { client } = await register('rp-key-rotation-op-sign-key', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    await client.authorizationCallback(redirect_uri, params);

    timekeeper.travel(Date.now() + (61 * 1000)); // travel one minute from now, making the cached keystore stale

    const secondAuthorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);
    const secondParams = client.callbackParams(secondAuthorization.headers.location);
    await client.authorizationCallback(redirect_uri, secondParams);
  });

  it('rp-key-rotation-op-enc-key');
});
