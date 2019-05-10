const { strict: assert } = require('assert');

const {
  noFollow,
  redirect_uri,
  register,
  describe,
  authorize,
  callback,
  it,
} = require('./helper');

describe('Claim Types', function () {
  it('rp-claims-aggregated', async function () {
    const response_type = 'code';
    const { client } = await register('rp-claims-aggregated', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    const userinfo = await client.userinfo(tokens);
    const aggregated = await client.unpackAggregatedClaims(userinfo);
    assert(aggregated.shoe_size);
    assert(aggregated.eye_color);
  });

  it('rp-claims-distributed', async function () {
    const response_type = 'code';
    const { client } = await register('rp-claims-distributed', { });
    const authorization = await authorize(client.authorizationUrl({ redirect_uri, response_type }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await callback(client, redirect_uri, params, { response_type });
    const userinfo = await client.userinfo(tokens);
    const distributed = await client.fetchDistributedClaims(userinfo);
    assert(distributed.age);
  });
});
