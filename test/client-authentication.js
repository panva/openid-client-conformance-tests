const { strict: assert } = require('assert');

const { forEach } = require('lodash');
const jose = require('jose'); // eslint-disable-line import/no-extraneous-dependencies
const {
  noFollow,
  redirect_uri,
  register,
  describe,
  authorize,
  callback,
  it,
  random,
} = require('./helper');

describe('Client Authentication', function () {
  describe('rp-token_endpoint-client_secret_basic', function () {
    forEach({
      '@code-basic': 'code',
      '@code+id_token-hybrid': 'code id_token',
      '@code+token-hybrid': 'code token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-token_endpoint-client_secret_basic', { token_endpoint_auth_method: 'client_secret_basic' });
        assert.equal(client.token_endpoint_auth_method, 'client_secret_basic');
        const nonce = random();
        const authorization = await authorize(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await callback(client, redirect_uri, params, { nonce, response_type });
        assert(tokens);
      });
    });
  });

  it('rp-token_endpoint-client_secret_jwt', async function () {
    const response_type = 'code';
    const { client } = await register('rp-token_endpoint-client_secret_jwt', { token_endpoint_auth_method: 'client_secret_jwt' });
    assert.equal(client.token_endpoint_auth_method, 'client_secret_jwt');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    assert(tokens);
  });

  it('rp-token_endpoint-client_secret_post', async function () {
    const response_type = 'code';
    const { client } = await register('rp-token_endpoint-client_secret_post', { token_endpoint_auth_method: 'client_secret_post' });
    assert.equal(client.token_endpoint_auth_method, 'client_secret_post');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    assert(tokens);
  });

  it('rp-token_endpoint-private_key_jwt', async function () {
    const keystore = new jose.JWKS.KeyStore();
    await keystore.generate('EC');
    const response_type = 'code';
    const { client } = await register('rp-token_endpoint-private_key_jwt', { token_endpoint_auth_method: 'private_key_jwt' }, keystore);
    assert.equal(client.token_endpoint_auth_method, 'private_key_jwt');
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    assert(tokens);
  });
});
