'use strict';

const { forEach } = require('lodash');
const {
  noFollow,
  redirect_uri,
  redirect_uris,
  register,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('scope Request Parameter', function () {
  describe('rp-scope-userinfo-claims', function () {
    forEach({
      '@basic': ['code', ['authorization_code']],
      '@implicit': ['id_token token', ['implicit']],
      '@hybrid': ['code id_token', ['implicit', 'authorization_code']],
    }, (setup, profile) => {
      const [response_type, grant_types] = setup;

      it(profile, async function () {
        const { client } = await register('rp-scope-userinfo-claims', { redirect_uris, grant_types, response_types: [response_type] });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type, scope: 'openid email' }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
        const userinfo = await client.userinfo(tokens);
        assert(userinfo.email);
      });
    });
  });
});
