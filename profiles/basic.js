'use strict';

/* eslint-disable func-names, prefer-arrow-callback */

const { Issuer } = require('openid-client');
const {
  clear,
  download,
  noFollow,
  redirect_uri,
  redirect_uris,
  register,
  reject,
  root,
  rpId,
} = require('./test_helper')('basic');
const assert = require('assert');
const got = require('got');

describe('RP Tests - BASIC profile', function () {
  this.timeout(10000);

  before(clear);
  after(download);

  describe('Response Type and Response Mode', function () {
    it('rp-response_type-code', async function () {
      const { client } = await register('rp-response_type-code', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);
      const params = client.callbackParams(authorization.headers.location);
      assert(params.code);
    });
  });

  describe('scope Request Parameter', function () {
    it('rp-scope-userinfo-claims', async function () { // optional
      const { client } = await register('rp-scope-userinfo-claims', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri, scope: 'openid email' }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      const tokens = await client.authorizationCallback(redirect_uri, params);
      const userinfo = await client.userinfo(tokens);
      assert(userinfo.email);
    });
  });

  describe('nonce Request Parameter', function () {
    it('rp-nonce-invalid', async function () {
      const { client } = await register('rp-nonce-invalid', { redirect_uris });
      const nonce = String(Math.random());
      const authorization = await got(client.authorizationUrl({ redirect_uri, nonce }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
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
      const { client } = await register('rp-token_endpoint-client_secret_basic', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      const tokens = await client.authorizationCallback(redirect_uri, params);
      assert(tokens);
    });
  });

  describe('ID Token', function () {
    it('rp-id_token-bad-sig-rs256', async function () { // optional
      const { client } = await register('rp-id_token-bad-sig-rs256', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      try {
        await client.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'invalid signature');
      }
    });

    it('rp-id_token-sig-none', async function () { // optional
      const issuer = await Issuer.discover(`${root}/${rpId}/rp-id_token-sig-none`);
      const client = await issuer.Client.register({ redirect_uris, id_token_signed_response_alg: 'none' });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      const tokens = await client.authorizationCallback(redirect_uri, params);
      assert(tokens.id_token);
    });

    it('rp-id_token-issuer-mismatch', async function () {
      const { client } = await register('rp-id_token-issuer-mismatch', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      try {
        await client.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'unexpected iss value');
      }
    });

    it('rp-id_token-iat', async function () {
      const { client } = await register('rp-id_token-iat', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      try {
        await client.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property iat');
      }
    });

    it('rp-id_token-aud', async function () {
      const { client } = await register('rp-id_token-aud', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      try {
        await client.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'aud is missing the client_id');
      }
    });

    it('rp-id_token-sub', async function () {
      const { client } = await register('rp-id_token-sub', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      try {
        await client.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property sub');
      }
    });

    it('rp-id_token-kid-absent-single-jwks', async function () { // optional
      const { client } = await register('rp-id_token-kid-absent-single-jwks', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      await client.authorizationCallback(redirect_uri, params);
    });

    it('rp-id_token-kid-absent-multiple-jwks', async function () {
      const { client } = await register('rp-id_token-kid-absent-multiple-jwks', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      try {
        await client.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'multiple matching keys, kid must be provided');
      }
    });
  });

  describe('UserInfo Endpoint', function () {
    it('rp-userinfo-bearer-header', async function () {
      const { client } = await register('rp-userinfo-bearer-header', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      const tokens = await client.authorizationCallback(redirect_uri, params);
      await client.userinfo(tokens, { via: 'header' });
    });

    it('rp-userinfo-bearer-body', async function () {
      const { client } = await register('rp-userinfo-bearer-body', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      const tokens = await client.authorizationCallback(redirect_uri, params);
      await client.userinfo(tokens, { via: 'body', verb: 'post' });
    });

    it('rp-userinfo-bad-sub-claim', async function () {
      const { client } = await register('rp-userinfo-bad-sub-claim', { redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);

      const params = client.callbackParams(authorization.headers.location);
      const tokens = await client.authorizationCallback(redirect_uri, params);
      try {
        await client.userinfo(tokens);
        reject();
      } catch (err) {
        assert.equal(err.message, 'userinfo sub mismatch');
      }
    });
  });
});
