'use strict';

const base64url = require('base64url');
const {
  noFollow,
  redirect_uri,
  redirect_uris,
  register,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('claims Request Parameter', function () {
  it('rp-claims_request-id_token', async function () {
    const { client } = await register('rp-claims_request-id_token', { redirect_uris });
    const authorization = await got(client.authorizationUrl({ claims: { id_token: { name: null } }, redirect_uri, response_type: 'code' }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const { id_token: idToken } = await client.authorizationCallback(redirect_uri, params);
    assert(JSON.parse(base64url.decode(idToken.split('.')[1])).name);
  });

  it('rp-claims_request-userinfo', async function () {
    const { client } = await register('rp-claims_request-userinfo', { redirect_uris });
    const authorization = await got(client.authorizationUrl({ claims: { userinfo: { name: null } }, redirect_uri, response_type: 'code' }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await client.authorizationCallback(redirect_uri, params);
    const userinfo = await client.userinfo(tokens);
    assert(userinfo.name);
  });
});
