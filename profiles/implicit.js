'use strict';

/* eslint-disable func-names, prefer-arrow-callback */

const {
  clear,
  download,
  noFollow,
  redirect_uri,
  redirect_uris,
  register,
  reject,
} = require('./test_helper')('implicit');

const assert = require('assert');
const got = require('got');

describe('RP Tests IMPLICIT profile', function () {
  this.timeout(10000);

  before(clear);
  after(download);

  describe('Response Type and Response Mode', function () {
    it('rp-response_type-id_token', async function () {
      const { client } = await register('rp-response_type-id_token', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'id_token', nonce: String(Math.random()) }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      assert(params.id_token);
    });

    it('rp-response_type-id_token+token', async function () {
      const { client } = await register('rp-response_type-id_token+token', { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'id_token token', nonce: String(Math.random()) }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      assert(params.id_token);
      assert(params.access_token);
    });
  });

  describe('nonce Request Parameter', function () {
    it('rp-nonce-unless-code-flow', async function () {
      const { client } = await register('rp-nonce-unless-code-flow', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      try {
        client.authorizationUrl({ redirect_uri, response_type: 'id_token' });
        reject();
      } catch (err) {
        assert.equal(err.message, 'nonce MUST be provided for implicit and hybrid flows');
      }
      const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
      assert(tokens);
    });

    it('rp-nonce-invalid', async function () {
      const { client } = await register('rp-nonce-invalid', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'id_token', nonce }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'nonce mismatch');
      }
    });
  });

  describe('ID Token', function () {
    it('rp-id_token-bad-sig-rs256', async function () { // optional
      const { client } = await register('rp-id_token-bad-sig-rs256', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'invalid signature');
      }
    });

    it('rp-id_token-bad-at_hash', async function () { // optional
      const { client } = await register('rp-id_token-bad-at_hash', { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'at_hash mismatch');
      }
    });

    it('rp-id_token-issuer-mismatch', async function () {
      const { client } = await register('rp-id_token-issuer-mismatch', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'unexpected iss value');
      }
    });

    it('rp-id_token-iat', async function () {
      const { client } = await register('rp-id_token-iat', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property iat');
      }
    });

    it('rp-id_token-aud', async function () {
      const { client } = await register('rp-id_token-aud', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'aud is missing the client_id');
      }
    });

    it('rp-id_token-sub', async function () { // broken, does not allow other than code response_types;
      const { client } = await register('rp-id_token-sub', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property sub');
      }
    });

    it('rp-id_token-kid-absent-single-jwks', async function () { // optional
      const { client } = await register('rp-id_token-kid-absent-single-jwks', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      await client.authorizationCallback(redirect_uri, params, { nonce });
    });

    it('rp-id_token-kid-absent-multiple-jwks', async function () {
      const { client } = await register('rp-id_token-kid-absent-multiple-jwks', { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'multiple matching keys, kid must be provided');
      }
    });
  });

  describe('UserInfo Endpoint', function () {
    it('rp-userinfo-bearer-header', async function () {
      const { client } = await register('rp-userinfo-bearer-header', { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
      await client.userinfo(tokens, { via: 'header' });
    });

    it('rp-userinfo-bearer-body', async function () {
      const { client } = await register('rp-userinfo-bearer-body', { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
      await client.userinfo(tokens, { via: 'body', verb: 'post' });
    });

    it('rp-userinfo-bad-sub-claim', async function () {
      const { client } = await register('rp-userinfo-bad-sub-claim', { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
      try {
        await client.userinfo(tokens);
        reject();
      } catch (err) {
        assert.equal(err.message, 'userinfo sub mismatch');
      }
    });
  });
});
