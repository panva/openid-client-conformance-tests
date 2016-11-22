'use strict';

const { forEach } = require('lodash');
const {
  noFollow,
  redirect_uri,
  redirect_uris,
  register,
  reject,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('UserInfo Endpoint', function () {
  describe('rp-userinfo-bearer-header', function () {
    forEach({
      '@basic': ['code', ['authorization_code']],
      '@implicit': ['id_token token', ['implicit']],
      '@hybrid': ['code id_token', ['implicit', 'authorization_code']],
    }, (setup, profile) => {
      const [response_type, grant_types] = setup;

      it(profile, async function () {
        const { client } = await register('rp-userinfo-bearer-header', { redirect_uris, grant_types, response_types: [response_type] });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
        await client.userinfo(tokens, { via: 'header' });
      });
    });
  });

  describe('rp-userinfo-bearer-body', function () {
    forEach({
      '@basic': ['code', ['authorization_code']],
      '@implicit': ['id_token token', ['implicit']],
      '@hybrid': ['code id_token', ['implicit', 'authorization_code']],
    }, (setup, profile) => {
      const [response_type, grant_types] = setup;

      it(profile, async function () {
        const { client } = await register('rp-userinfo-bearer-body', { redirect_uris, grant_types, response_types: [response_type] });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
        await client.userinfo(tokens, { via: 'body', verb: 'post' });
      });
    });
  });

  it('rp-userinfo-sig @config,@dynamic', async function () {
    const { client } = await register('rp-userinfo-sig', { redirect_uris, userinfo_signed_response_alg: 'HS256' });
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await client.authorizationCallback(redirect_uri, params);
    await client.userinfo(tokens);
  });

  it('rp-userinfo-sig+enc');

  it('rp-userinfo-enc');

  describe('rp-userinfo-bad-sub-claim', function () {
    forEach({
      '@basic': ['code', ['authorization_code']],
      '@implicit': ['id_token token', ['implicit']],
      '@hybrid': ['code id_token', ['implicit', 'authorization_code']],
    }, (setup, profile) => {
      const [response_type, grant_types] = setup;

      it(profile, async function () {
        const { client } = await register('rp-userinfo-bad-sub-claim', { redirect_uris, grant_types, response_types: [response_type] });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

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
});
