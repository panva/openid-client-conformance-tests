const { strict: assert } = require('assert');

const base64url = require('base64url');
const {
  noFollow,
  redirect_uri,
  register,
  describe,
  authorize,
  callback,
  it,
} = require('./helper');

describe('claims Request Parameter', function () {
  it('rp-claims_request-id_token', async function () {
    const response_type = 'code';
    const { client } = await register('rp-claims_request-id_token', { });
    const authorization = await authorize(client.authorizationUrl({ claims: { id_token: { name: null } }, redirect_uri, response_type }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const { id_token: idToken } = await callback(client, redirect_uri, params, { response_type });
    assert(JSON.parse(base64url.decode(idToken.split('.')[1])).name);
  });

  it('rp-claims_request-userinfo', async function () {
    const response_type = 'code';
    const { client } = await register('rp-claims_request-userinfo', { });
    const authorization = await authorize(client.authorizationUrl({ claims: { userinfo: { name: null } }, redirect_uri, response_type }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    const userinfo = await client.userinfo(tokens);
    assert(userinfo.name);
  });
});
