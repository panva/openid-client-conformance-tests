'use strict';

const { forEach } = require('lodash');
const {
  noFollow,
  redirect_uri,
  register,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('scope Request Parameter', function () {
  describe('rp-scope-userinfo-claims', function () {
    forEach({
      '@basic': 'code',
      '@implicit': 'id_token token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-scope-userinfo-claims', { });
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
