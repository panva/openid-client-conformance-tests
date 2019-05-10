const { forEach } = require('lodash');
const { strict: assert } = require('assert');
const url = require('url');
const got = require('got');
const querystring = require('querystring');
const {
  noFollow,
  redirect_uri,
  register,
  describe,
  random,
  authorize,
  reject,
  callback,
  it,
} = require('./helper');

describe('Response Type and Response Mode', function () {
  it('rp-response_type-code @code-basic', async function () {
    const { client } = await register('rp-response_type-code', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    assert(params.code);
  });

  it('rp-response_type-id_token @id_token-implicit', async function () {
    const { client } = await register('rp-response_type-id_token', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type: 'id_token', nonce: random() }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.id_token);
  });

  it('rp-response_type-id_token+token @id_token+token-implicit', async function () {
    const { client } = await register('rp-response_type-id_token+token', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type: 'id_token token', nonce: random() }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.id_token);
    assert(params.access_token);
  });

  it('rp-response_type-code+id_token @code+id_token-hybrid', async function () {
    const { client } = await register('rp-response_type-code+id_token', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type: 'code id_token', nonce: random() }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.id_token);
    assert(params.code);
  });

  it('rp-response_type-code+token @code+token-hybrid', async function () {
    const { client } = await register('rp-response_type-code+token', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type: 'code token', nonce: random() }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.code);
    assert(params.access_token);
  });

  it('rp-response_type-code+id_token+token @code+id_token+token-hybrid', async function () {
    const { client } = await register('rp-response_type-code+id_token+token', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type: 'code id_token token', nonce: random() }), noFollow);

    const params = client.callbackParams(authorization.headers.location.replace('#', '?'));
    assert(params.id_token);
    assert(params.code);
    assert(params.access_token);
  });

  describe('rp-response_mode-form_post', function () {
    forEach({
      '@code-basic': 'code',
      '@id_token-implicit': 'id_token',
      '@id_token+token-implicit': 'id_token token',
      '@code+id_token-hybrid': 'code id_token',
      '@code+token-hybrid': 'code token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-response_mode-form_post', { });

        const nonce = random();
        const request = client.authorizationUrl({
          response_mode: 'form_post', redirect_uri, response_type, nonce,
        });
        const { pathname, query } = url.parse(request, true);
        log('authentication request to', pathname);
        log('authentication request parameters', JSON.stringify(query, null, 4));
        const authorization = await got(request, noFollow);

        authorization.method = 'POST';

        authorization.body = querystring.stringify(
          authorization.body.match(/<input type="hidden" name="\w+" value=".+"\/>/g).reduce((acc, match) => {
            const [, key, value] = match.match(/name="(\w+)" value="(.+)"/);
            acc[key] = value;
            return acc;
          }, {}),
        );

        const params = client.callbackParams(authorization);
        log('authentication response', JSON.stringify(params, null, 4));
        const tokens = await callback(client, redirect_uri, params, { nonce, response_type });
        assert(tokens);
      });
    });
  });

  describe('rp-response_mode-form_post-error', function () {
    forEach({
      '@code-basic': 'code',
      '@id_token-implicit': 'id_token',
      '@id_token+token-implicit': 'id_token token',
      '@code+id_token-hybrid': 'code id_token',
      '@code+token-hybrid': 'code token',
      '@code+id_token+token-hybrid': 'code id_token token',
    }, (response_type, profile) => {
      it(profile, async function () {
        const { client } = await register('rp-response_mode-form_post-error', { });

        const nonce = random();
        const state = random();
        const request = client.authorizationUrl({
          response_mode: 'form_post', redirect_uri, response_type, nonce, state, prompt: 'none', max_age: 0,
        });
        const { pathname, query } = url.parse(request, true);
        log('authentication request to', pathname);
        log('authentication request parameters', JSON.stringify(query, null, 4));
        const authorization = await got(request, noFollow);

        authorization.method = 'POST';

        authorization.body = querystring.stringify(
          authorization.body.match(/<input type="hidden" name="\w+" value=".+"\/>/g).reduce((acc, match) => {
            const [, key, value] = match.match(/name="(\w+)" value="(.+)"/);
            acc[key] = value;
            return acc;
          }, {}),
        );

        const params = client.callbackParams(authorization);
        log('authentication response', JSON.stringify(params, null, 4));
        try {
          await callback(client, redirect_uri, params, { nonce, response_type, state });
          reject();
        } catch (err) {
          assert.equal(err.message, 'login_required');
        }
      });
    });
  });
});
