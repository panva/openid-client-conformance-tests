'use strict';

const assert = require('assert');
const jose = require('node-jose');

const {
  gist,
  redirect_uri,
  register,
  noFollow,
  describe,
  authorize,
  authorizationCallback,
  it,
} = require('./helper');

describe('request_uri Request Parameter', function () {
  it('rp-request_uri-enc', async function () {
    const keystore = jose.JWK.createKeyStore();
    await keystore.generate('RSA', 1024);

    const { client } = await register('rp-request_uri-enc', {
      request_object_signing_alg: 'none',
      request_object_encryption_alg: 'RSA1_5',
      request_object_encryption_enc: 'A128CBC-HS256',
    }, keystore);

    const requestObject = await client.requestObject({ state: 'foobar' });

    const request_uri = await gist(requestObject);
    assert.equal(client.request_object_signing_alg, 'none');
    assert.equal(client.request_object_encryption_alg, 'RSA1_5');
    assert.equal(client.request_object_encryption_enc, 'A128CBC-HS256');

    const authorization = await authorize(client.authorizationUrl({ redirect_uri, request_uri }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    await authorizationCallback(client, redirect_uri, params, { state: 'foobar' });
  });

  it('rp-request_uri-sig+enc', async function () {
    const keystore = jose.JWK.createKeyStore();
    await keystore.generate('RSA', 1024);

    const { client } = await register('rp-request_uri-sig+enc', {
      request_object_signing_alg: 'RS256',
      request_object_encryption_alg: 'RSA1_5',
      request_object_encryption_enc: 'A128CBC-HS256',
    }, keystore);

    const requestObject = await client.requestObject({ state: 'foobar' });

    const request_uri = await gist(requestObject);
    assert.equal(client.request_object_signing_alg, 'RS256');
    assert.equal(client.request_object_encryption_alg, 'RSA1_5');
    assert.equal(client.request_object_encryption_enc, 'A128CBC-HS256');

    const authorization = await authorize(client.authorizationUrl({ redirect_uri, request_uri }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    await authorizationCallback(client, redirect_uri, params, { state: 'foobar' });
  });

  it('rp-request_uri-unsigned @code-dynamic', async function () {
    const { client } = await register('rp-request_uri-unsigned', { request_object_signing_alg: 'none' });
    const requestObject = await client.requestObject({ state: 'foobar' });
    const request_uri = await gist(requestObject);
    assert.equal(client.request_object_signing_alg, 'none');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, request_uri }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    await authorizationCallback(client, redirect_uri, params, { state: 'foobar' });
  });

  it('rp-request_uri-sig @code-dynamic', async function () {
    const keystore = jose.JWK.createKeyStore();
    await keystore.generate('RSA', 1024, {
      use: 'sig',
      alg: 'RS256',
    });

    const { client } = await register('rp-request_uri-sig', { request_object_signing_alg: 'RS256' }, keystore);
    const requestObject = await client.requestObject({ state: 'foobar' });
    const request_uri = await gist(requestObject);
    assert.equal(client.request_object_signing_alg, 'RS256');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, request_uri }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    await authorizationCallback(client, redirect_uri, params, { state: 'foobar' });
  });
});
