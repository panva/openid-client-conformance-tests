'use strict';

const { forEach } = require('lodash');
const jose = require('node-jose'); // eslint-disable-line import/no-extraneous-dependencies
const {
  noFollow,
  redirect_uri,
  redirect_uris,
  register,
  reject,
  describe,
  authorize,
  authorizationCallback,
  userinfoCall,
  it,
} = require('./helper');

const assert = require('assert');

describe('UserInfo Endpoint', function () {
  describe('rp-userinfo-bearer-header', function () {
    forEach({
      '@code-basic': 'code',
      '@id_token+token-implicit': 'id_token token',
      '@code+id_token-hybrid': 'code id_token',
      '@code+token-hybrid': 'code token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-userinfo-bearer-header', { });
        const nonce = String(Math.random());
        const authorization = await authorize(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await authorizationCallback(client, redirect_uri, params, { nonce, response_type });
        const userinfo = await userinfoCall(client, tokens, { via: 'header' });
        assert(userinfo);
      });
    });
  });

  describe('rp-userinfo-bearer-body', function () {
    forEach({
      '@code-basic': 'code',
      '@id_token+token-implicit': 'id_token token',
      '@code+id_token-hybrid': 'code id_token',
      '@code+token-hybrid': 'code token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-userinfo-bearer-body', { });
        const nonce = String(Math.random());
        const authorization = await authorize(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await authorizationCallback(client, redirect_uri, params, { nonce, response_type });
        const userinfo = await userinfoCall(client, tokens, { via: 'body', verb: 'post' });
        assert(userinfo);
      });
    });
  });

  it('rp-userinfo-sig @code-config,@code-dynamic', async function () {
    const response_type = 'code';
    const { client } = await register('rp-userinfo-sig', { redirect_uris, userinfo_signed_response_alg: 'HS256' });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await authorizationCallback(client, redirect_uri, params, { response_type });
    const userinfo = await userinfoCall(client, tokens);
    assert(userinfo);
  });

  it('rp-userinfo-sig+enc', async function () {
    const response_type = 'code';
    const keystore = jose.JWK.createKeyStore();
    await keystore.generate('RSA', 512);
    const { client } = await register('rp-userinfo-sig+enc', { userinfo_signed_response_alg: 'RS256', userinfo_encrypted_response_alg: 'RSA1_5', redirect_uris }, keystore);
    assert.equal(client.userinfo_signed_response_alg, 'RS256');
    assert.equal(client.userinfo_encrypted_response_alg, 'RSA1_5');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await authorizationCallback(client, redirect_uri, params, { response_type });
    const userinfo = await userinfoCall(client, tokens);
    assert(userinfo.sub);
  });

  it('rp-userinfo-enc', async function () {
    const response_type = 'code';
    const keystore = jose.JWK.createKeyStore();
    await keystore.generate('RSA', 512);
    const { client } = await register('rp-userinfo-enc', { userinfo_signed_response_alg: 'none', userinfo_encrypted_response_alg: 'RSA1_5', redirect_uris }, keystore);
    assert.equal(client.userinfo_signed_response_alg, 'none');
    assert.equal(client.userinfo_encrypted_response_alg, 'RSA1_5');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await authorizationCallback(client, redirect_uri, params, { response_type });
    const userinfo = await userinfoCall(client, tokens);
    assert(userinfo.sub);
  });

  describe('rp-userinfo-bad-sub-claim', function () {
    forEach({
      '@code-basic': 'code',
      '@id_token+token-implicit': 'id_token token',
      '@code+id_token-hybrid': 'code id_token',
      '@code+token-hybrid': 'code token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-userinfo-bad-sub-claim', { });
        const nonce = String(Math.random());
        const authorization = await authorize(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await authorizationCallback(client, redirect_uri, params, { nonce, response_type });
        try {
          await userinfoCall(client, tokens);
          reject();
        } catch (err) {
          assert.equal(err.message, 'userinfo sub mismatch');
        }
      });
    });
  });
});
