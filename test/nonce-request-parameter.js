const { strict: assert } = require('assert');

const { forEach } = require('lodash');
const {
  noFollow,
  redirect_uri,
  register,
  random,
  reject,
  describe,
  authorize,
  callback,
  it,
} = require('./helper');

describe('nonce Request Parameter', function () {
  describe.skip('rp-nonce-unless-code-flow', function () {
    forEach({
      '@id_token-implicit': 'id_token',
      '@id_token+token-implicit': 'id_token token',
      '@code+id_token-hybrid': 'code id_token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-nonce-unless-code-flow', { });
        const nonce = random();
        try {
          client.authorizationUrl({ redirect_uri, response_type });
          reject();
        } catch (err) {
          assert.equal(err.message, 'nonce MUST be provided for implicit and hybrid flows');
        }
        const authorization = await authorize(client.authorizationUrl({ nonce, redirect_uri, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await callback(client, redirect_uri, params, { nonce, response_type });
        assert(tokens);
      });
    });
  });

  describe('rp-nonce-invalid', function () {
    forEach({
      '@code-basic': 'code',
      '@id_token-implicit': 'id_token',
      '@id_token+token-implicit': 'id_token token',
      '@code+id_token-hybrid': 'code id_token',
      '@code+token-hybrid': 'code token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-nonce-invalid', { });
        const nonce = random();
        const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type, nonce }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        try {
          await callback(client, redirect_uri, params, { nonce, response_type });
          reject();
        } catch (err) {
          assert.equal(err.message, `nonce mismatch, expected ${nonce}, got: 012345678`);
        }
      });
    });
  });
});
