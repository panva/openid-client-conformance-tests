'use strict';

const { forEach } = require('lodash');
const {
  noFollow,
  redirect_uri,
  register,
  reject,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('nonce Request Parameter', function () {
  describe('rp-nonce-unless-code-flow', function () {
    forEach({
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-nonce-unless-code-flow', { });
        const nonce = String(Math.random());
        try {
          client.authorizationUrl({ redirect_uri, response_type });
          reject();
        } catch (err) {
          assert.equal(err.message, 'nonce MUST be provided for implicit and hybrid flows');
        }
        const authorization = await got(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
        assert(tokens);
      });
    });
  });

  describe('rp-nonce-invalid', function () {
    forEach({
      '@implicit': 'id_token',
      '@hybrid': 'code id_token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-nonce-invalid', { });
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, response_type, nonce }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await client.authorizationCallback(redirect_uri, params, { nonce });
          reject();
        } catch (err) {
          assert.equal(err.message, 'nonce mismatch');
        }
      });
    });
  });
});
