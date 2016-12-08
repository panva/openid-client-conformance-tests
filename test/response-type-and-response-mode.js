'use strict';

const {
  noFollow,
  redirect_uri,
  register,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('Response Type and Response Mode', function () {
  it('rp-response_type-code @code-basic', async function () {
    const { client } = await register('rp-response_type-code', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    assert(params.code);
  });

  it('rp-response_type-id_token @id_token-implicit', async function () {
    const { client } = await register('rp-response_type-id_token', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'id_token', nonce: String(Math.random()) }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.id_token);
  });

  it('rp-response_type-id_token+token @id_token+token-implicit', async function () {
    const { client } = await register('rp-response_type-id_token+token', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'id_token token', nonce: String(Math.random()) }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.id_token);
    assert(params.access_token);
  });

  it('rp-response_type-code+id_token @code+id_token-hybrid', async function () {
    const { client } = await register('rp-response_type-code+id_token', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code id_token', nonce: String(Math.random()) }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.id_token);
    assert(params.code);
  });

  it('rp-response_type-code+token @code+token-hybrid', async function () {
    const { client } = await register('rp-response_type-code+token', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code token', nonce: String(Math.random()) }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.code);
    assert(params.access_token);
  });

  it('rp-response_type-code+id_token+token @code+id_token+token-hybrid', async function () {
    const { client } = await register('rp-response_type-code+id_token+token', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code id_token token', nonce: String(Math.random()) }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.id_token);
    assert(params.code);
    assert(params.access_token);
  });
});
