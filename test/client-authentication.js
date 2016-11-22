'use strict';

const { forEach } = require('lodash');
const jose = require('node-jose');
const {
  noFollow,
  redirect_uri,
  redirect_uris,
  register,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('Client Authentication', function () {
  describe('rp-token_endpoint-client_secret_basic', function () {
    forEach({
      '@basic': ['code', ['authorization_code']],
      '@hybrid': ['code id_token', ['implicit', 'authorization_code']],
    }, (setup, profile) => {
      const [response_type, grant_types] = setup;

      it(profile, async function () {
        const { client } = await register('rp-token_endpoint-client_secret_basic', { token_endpoint_auth_method: 'client_secret_basic', redirect_uris, grant_types, response_types: [response_type] });
        assert.equal(client.token_endpoint_auth_method, 'client_secret_basic');
        const nonce = String(Math.random());
        const authorization = await got(client.authorizationUrl({ redirect_uri, nonce, response_type }), noFollow);

        const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
        const tokens = await client.authorizationCallback(redirect_uri, params, { nonce });
        assert(tokens);
      });
    });
  });

  it('rp-token_endpoint-client_secret_jwt', async function () {
    const { client } = await register('rp-token_endpoint-client_secret_jwt', { token_endpoint_auth_method: 'client_secret_jwt', redirect_uris });
    assert.equal(client.token_endpoint_auth_method, 'client_secret_jwt');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await client.authorizationCallback(redirect_uri, params);
    assert(tokens);
  });

  it('rp-token_endpoint-client_secret_post', async function () {
    const { client } = await register('rp-token_endpoint-client_secret_post', { token_endpoint_auth_method: 'client_secret_post', redirect_uris });
    assert.equal(client.token_endpoint_auth_method, 'client_secret_post');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await client.authorizationCallback(redirect_uri, params);
    assert(tokens);
  });

  it('rp-token_endpoint-private_key_jwt', async function () {
    const keystore = jose.JWK.createKeyStore();
    await keystore.generate('EC', 'P-256');
    const { client } = await register('rp-token_endpoint-private_key_jwt', { token_endpoint_auth_method: 'private_key_jwt', redirect_uris }, keystore);
    assert.equal(client.token_endpoint_auth_method, 'private_key_jwt');
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);

    const params = client.callbackParams(authorization.headers.location);
    const tokens = await client.authorizationCallback(redirect_uri, params);
    assert(tokens);
  });
});
