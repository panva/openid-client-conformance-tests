'use strict';

const { forEach } = require('lodash');
const base64url = require('base64url');
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
      '@code-basic': 'code',
      '@id_token-implicit': 'id_token',
      '@id_token+token-implicit': 'id_token token',
      '@code+id_token-hybrid': 'code id_token',
      '@code+token-hybrid': 'code token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-scope-userinfo-claims', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type, scope: 'openid email' }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });

        const userinfo = await (async () => {
          if (tokens.access_token) {
            return await client.userinfo(tokens);
          }
          return JSON.parse(base64url.decode(tokens.id_token.split('.')[1]));
        })();
        assert(userinfo.email);
      });
    });
  });
});
