const { strict: assert } = require('assert');

const { forEach } = require('lodash');
const jose = require('jose'); // eslint-disable-line import/no-extraneous-dependencies
const {
  noFollow,
  redirect_uri,
  random,
  redirect_uris,
  register,
  reject,
  describe,
  authorize,
  callback,
  userinfoCall,
  it,
} = require('./helper');

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
        const nonce = random();
        const authorization = await authorize(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await callback(client, redirect_uri, params, { nonce, response_type });
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
        const nonce = random();
        const authorization = await authorize(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await callback(client, redirect_uri, params, { nonce, response_type });
        const userinfo = await userinfoCall(client, tokens, { via: 'body', method: 'post' });
        assert(userinfo);
      });
    });
  });

  it('rp-userinfo-sig @code-config,@code-dynamic', async function () {
    const response_type = 'code';
    const { client } = await register('rp-userinfo-sig', { redirect_uris, userinfo_signed_response_alg: 'HS256' });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    const userinfo = await userinfoCall(client, tokens);
    assert(userinfo);
  });

  it('rp-userinfo-sig+enc', async function () {
    const response_type = 'code';
    const keystore = new jose.JWKS.KeyStore();
    await keystore.generate('RSA');
    const { client } = await register('rp-userinfo-sig+enc', { userinfo_signed_response_alg: 'RS256', userinfo_encrypted_response_alg: 'RSA1_5', redirect_uris }, keystore);
    assert.equal(client.userinfo_signed_response_alg, 'RS256');
    assert.equal(client.userinfo_encrypted_response_alg, 'RSA1_5');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    const userinfo = await userinfoCall(client, tokens);
    assert(userinfo.sub);
  });

  it('rp-userinfo-enc', async function () {
    const response_type = 'code';
    const keystore = new jose.JWKS.KeyStore();
    await keystore.generate('RSA');
    const { client } = await register('rp-userinfo-enc', { userinfo_signed_response_alg: 'none', userinfo_encrypted_response_alg: 'RSA1_5', redirect_uris }, keystore);
    assert.equal(client.userinfo_signed_response_alg, 'none');
    assert.equal(client.userinfo_encrypted_response_alg, 'RSA1_5');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
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
        const nonce = random();
        const authorization = await authorize(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await callback(client, redirect_uri, params, { nonce, response_type });
        try {
          await userinfoCall(client, tokens);
          reject();
        } catch (err) {
          assert.equal(err.message, 'userinfo sub mismatch, expected 1b2fc9341a16ae4e30082965d537ae47c21a0f27fd43eab78330ed81751ae6db, got: foobar');
        }
      });
    });
  });
});
