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
} = require('./test_helper')('hybrid');

const assert = require('assert');
const got = require('got');

describe('RP Tests HYBRID profile', function () {
  this.timeout(10000);

  before(clear);
  after(download);

  describe('Response Type and Response Mode', function () {
    it('rp-response_type-code+id_token', async function () {
      const testId = 'rp-response_type-code+id_token';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code id_token', nonce: String(Math.random()) }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      assert(params.id_token);
      assert(params.code);
    });

    it('rp-response_type-code+token', async function () {
      const testId = 'rp-response_type-code+token';
      const { client } = await register(testId, { redirect_uris, response_types: ['code token'], grant_types: ['implicit', 'authorization_code'] });
      const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code token', nonce: String(Math.random()) }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      assert(params.code);
      assert(params.access_token);
    });

    it('rp-response_type-code+id_token+token', async function () {
      const testId = 'rp-response_type-code+id_token+token';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token token'], grant_types: ['implicit', 'authorization_code'] });
      const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code id_token token', nonce: String(Math.random()) }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      assert(params.id_token);
      assert(params.code);
      assert(params.access_token);
    });
  });

  describe('nonce Request Parameter', function () {
    it('rp-nonce-unless-code-flow', async function () {
      const testId = 'rp-nonce-unless-code-flow';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      try {
        client.authorizationUrl({ redirect_uri, response_type: 'code id_token' });
        reject();
      } catch (err) {
        assert.equal(err.message, 'nonce MUST be provided for implicit and hybrid flows');
      }
      const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
      assert(tokens);
    });

    it('rp-nonce-invalid', async function () {
      const testId = 'rp-nonce-invalid';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'nonce mismatch');
      }
    });
  });

  describe('Client Authentication', function () {
    it('rp-token_endpoint-client_secret_basic', async function () {
      const testId = 'rp-token_endpoint-client_secret_basic';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
      assert(tokens);
    });
  });

  describe('ID Token', function () {
    it('rp-id_token-bad-sig-rs256', async function () { // optional
      const testId = 'rp-id_token-bad-sig-rs256';
      const { client } = await register(testId, { redirect_uris, response_types: ['code token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'invalid signature');
      }
    });

    it('rp-id_token-bad-c_hash', async function () { // optional
      const testId = 'rp-id_token-bad-c_hash';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
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

    it('rp-id_token-bad-at_hash', async function () { // optional
      const testId = 'rp-id_token-bad-at_hash';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'at_hash mismatch');
      }
    });

    it('rp-id_token-issuer-mismatch', async function () {
      const testId = 'rp-id_token-issuer-mismatch';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'unexpected iss value');
      }
    });

    it('rp-id_token-iat', async function () {
      const testId = 'rp-id_token-iat';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property iat');
      }
    });

    it('rp-id_token-aud', async function () {
      const testId = 'rp-id_token-aud';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'aud is missing the client_id');
      }
    });

    it('rp-id_token-sub', async function () { // broken, does not allow other than code response_types;
      const testId = 'rp-id_token-sub';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await client.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property sub');
      }
    });

    it('rp-id_token-kid-absent-single-jwks', async function () { // optional
      const testId = 'rp-id_token-kid-absent-single-jwks';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      await client.authorizationCallback(redirect_uri, params, { nonce });
    });

    it('rp-id_token-kid-absent-multiple-jwks', async function () {
      const testId = 'rp-id_token-kid-absent-multiple-jwks';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type: 'code id_token' }), noFollow);

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
      const testId = 'rp-userinfo-bearer-header';
      const { client } = await register(testId, { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
      await client.userinfo(tokens, { via: 'header' });
    });

    it('rp-userinfo-bearer-body', async function () {
      const testId = 'rp-userinfo-bearer-body';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type: 'code id_token' }), noFollow);

      const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
      await client.userinfo(tokens, { via: 'body', verb: 'post' });
    });

    it('rp-userinfo-bad-sub-claim', async function () {
      const testId = 'rp-userinfo-bad-sub-claim';
      const { client } = await register(testId, { redirect_uris, response_types: ['code id_token'], grant_types: ['implicit', 'authorization_code'] });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type: 'code id_token' }), noFollow);

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
