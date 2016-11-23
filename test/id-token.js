'use strict';

const { forEach } = require('lodash');
const jose = require('node-jose');
const {
  noFollow,
  redirect_uri,
  register,
  reject,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('ID Token', function () {
  describe('rp-id_token-bad-sig-rs256', function () {
    forEach({
      '@basic': 'code',
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-id_token-bad-sig-rs256', { id_token_signed_response_alg: 'RS256' });
        assert.equal(client.id_token_signed_response_alg, 'RS256');
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await client.authorizationCallback(redirect_uri, params, { nonce });
          reject();
        } catch (err) {
          assert.equal(err.message, 'invalid signature');
        }
      });
    });
  });

  it('rp-id_token-bad-sig-hs256', async function () {
    const { client } = await register('rp-id_token-bad-sig-hs256', { id_token_signed_response_alg: 'HS256' });
    assert.equal(client.id_token_signed_response_alg, 'HS256');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    try {
      await client.authorizationCallback(redirect_uri, params);
      reject();
    } catch (err) {
      assert.equal(err.message, 'invalid signature');
    }
  });

  it('rp-id_token-sig+enc', async function () {
    const keystore = jose.JWK.createKeyStore();
    await keystore.generate('RSA', 512);
    const { client } = await register('rp-id_token-sig+enc', { id_token_signed_response_alg: 'RS256', id_token_encrypted_response_alg: 'RSA1_5' }, keystore);
    assert.equal(client.id_token_signed_response_alg, 'RS256');
    assert.equal(client.id_token_encrypted_response_alg, 'RSA1_5');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    await client.authorizationCallback(redirect_uri, params);
  });

  it('rp-id_token-sig-rs256', async function () {
    const { client } = await register('rp-id_token-sig-rs256', { id_token_signed_response_alg: 'RS256' });
    assert.equal(client.id_token_signed_response_alg, 'RS256');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    await client.authorizationCallback(redirect_uri, params);
  });

  it('rp-id_token-sig-hs256', async function () {
    const { client } = await register('rp-id_token-sig-hs256', { id_token_signed_response_alg: 'HS256' });
    assert.equal(client.id_token_signed_response_alg, 'HS256');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    await client.authorizationCallback(redirect_uri, params);
  });

  it('rp-id_token-sig-es256', async function () {
    const { client } = await register('rp-id_token-sig-es256', { id_token_signed_response_alg: 'ES256' });
    assert.equal(client.id_token_signed_response_alg, 'ES256');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    await client.authorizationCallback(redirect_uri, params);
  });

  it('rp-id_token-sig-none @basic,@config,@dynamic', async function () {
    const { client } = await register('rp-id_token-sig-none', { id_token_signed_response_alg: 'none' });
    assert.equal(client.id_token_signed_response_alg, 'none');
    const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await client.authorizationCallback(redirect_uri, params);
    assert(tokens.id_token);
  });

  it('rp-id_token-bad-c_hash @hybrid', async function () {
    const { client } = await register('rp-id_token-bad-c_hash', { });
    const nonce = String(Math.random());
    const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    try {
      await client.authorizationCallback(redirect_uri, params, { nonce });
      reject();
    } catch (err) {
      assert.equal(err.message, 'c_hash mismatch');
    }
  });

  describe('rp-id_token-bad-at_hash', function () {
    forEach({
      '@implicit': 'id_token token',
      '@hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-id_token-bad-at_hash', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await client.authorizationCallback(redirect_uri, params, { nonce });
          reject();
        } catch (err) {
          assert.equal(err.message, 'at_hash mismatch');
        }
      });
    });
  });

  describe('rp-id_token-issuer-mismatch', function () {
    forEach({
      '@basic': 'code',
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-id_token-issuer-mismatch', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await client.authorizationCallback(redirect_uri, params, { nonce });
          reject();
        } catch (err) {
          assert.equal(err.message, 'unexpected iss value');
        }
      });
    });
  });

  describe('rp-id_token-iat', function () {
    forEach({
      '@basic': 'code',
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-id_token-iat', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await client.authorizationCallback(redirect_uri, params, { nonce });
          reject();
        } catch (err) {
          assert.equal(err.message, 'missing required JWT property iat');
        }
      });
    });
  });


  it('rp-id_token-bad-sig-es256', async function () {
    const { client } = await register('rp-id_token-bad-sig-es256', { id_token_signed_response_alg: 'ES256' });
    assert.equal(client.id_token_signed_response_alg, 'ES256');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    try {
      await client.authorizationCallback(redirect_uri, params);
      reject();
    } catch (err) {
      assert.equal(err.message, 'invalid signature');
    }
  });

  describe('rp-id_token-aud', function () {
    forEach({
      '@basic': 'code',
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-id_token-aud', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await client.authorizationCallback(redirect_uri, params, { nonce });
          reject();
        } catch (err) {
          assert.equal(err.message, 'aud is missing the client_id');
        }
      });
    });
  });

  describe('rp-id_token-sub', function () {
    forEach({
      '@basic': 'code',
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-id_token-sub', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await client.authorizationCallback(redirect_uri, params, { nonce });
          reject();
        } catch (err) {
          assert.equal(err.message, 'missing required JWT property sub');
        }
      });
    });
  });

  describe('rp-id_token-kid-absent-single-jwks', function () {
    forEach({
      '@basic': 'code',
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-id_token-kid-absent-single-jwks', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        await client.authorizationCallback(redirect_uri, params, { nonce });
      });
    });
  });

  describe('rp-id_token-kid-absent-multiple-jwks', function () {
    forEach({
      '@basic': 'code',
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-id_token-kid-absent-multiple-jwks', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await client.authorizationCallback(redirect_uri, params, { nonce });
          reject();
        } catch (err) {
          assert.equal(err.message, 'multiple matching keys, kid must be provided');
        }
      });
    });
  });
});
