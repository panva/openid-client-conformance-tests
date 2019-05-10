const jose = require('@panva/jose'); // eslint-disable-line import/no-extraneous-dependencies
const { strict: assert } = require('assert');
const timekeeper = require('timekeeper');
const {
  register,
  random,
  echo,
  noFollow,
  redirect_uri,
  describe,
  authorize,
  callback,
  it,
  syncTime,
} = require('./helper');

afterEach(syncTime);

describe('Key Rotation', function () {
  it('rp-key-rotation-op-sign-key @code-config,@code-dynamic', async function () {
    const response_type = 'code';
    const { client } = await register('rp-key-rotation-op-sign-key', { });
    let authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);
    let params = client.callbackParams(authorization.headers.location);
    await callback(client, redirect_uri, params, { response_type });

    // await issuer.keystore(true);
    timekeeper.travel(Date.now() + (61 * 1000)); // travel one minute from now, making the cached keystore stale

    authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);
    params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    assert(tokens);
  });

  it('rp-key-rotation-op-sign-key-native @code-config,@code-dynamic', async function () {
    const response_type = 'code';
    const { client } = await register('rp-key-rotation-op-sign-key-native', { });
    let authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);
    let params = client.callbackParams(authorization.headers.location);
    await callback(client, redirect_uri, params, { response_type });

    timekeeper.travel(Date.now() + (61 * 1000)); // travel one minute from now, making the cached keystore stale

    authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);
    params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    assert(tokens);
  });

  it('rp-key-rotation-op-enc-key', async function () {
    const response_type = 'code';
    const keystore = new jose.JWKS.KeyStore();
    await keystore.generate('RSA');

    const { issuer, client } = await register('rp-key-rotation-op-enc-key', {
      request_object_signing_alg: 'RS256',
      request_object_encryption_alg: 'RSA-OAEP',
      request_object_encryption_enc: 'A128CBC-HS256',
    }, keystore);
    assert.equal(client.request_object_signing_alg, 'RS256');
    assert.equal(client.request_object_encryption_alg, 'RSA-OAEP');
    assert.equal(client.request_object_encryption_enc, 'A128CBC-HS256');

    let state = random();
    let requestObject = await client.requestObject({ state });
    let request_uri = await echo.post(requestObject, 'application/jwt');

    let authorization = await authorize(client.authorizationUrl({ redirect_uri, request_uri, response_type }), noFollow);
    let params = client.callbackParams(authorization.headers.location);
    await callback(client, redirect_uri, params, { response_type, state });

    await issuer.keystore(true);

    state = random();
    requestObject = await client.requestObject({ state });
    request_uri = await echo.post(requestObject, 'application/jwt');

    authorization = await authorize(client.authorizationUrl({ redirect_uri, request_uri, response_type }), noFollow);
    params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type, state });
    assert(tokens);
  });
});
