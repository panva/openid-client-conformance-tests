'use strict';

const {
  noFollow,
  redirect_uri,
  register,
} = require('./helper');

const assert = require('assert');
const got = require('got');

describe('Claim Types', function () {
  it('rp-claims-aggregated', async function () {
    const { client } = await register('rp-claims-aggregated', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await client.authorizationCallback(redirect_uri, params);
    const userinfo = await client.userinfo(tokens);
    const aggregated = await client.unpackAggregatedClaims(userinfo);
    assert(aggregated.shoe_size);
    assert(aggregated.eye_color);
  });

  it('rp-claims-distributed', async function () {
    const { client } = await register('rp-claims-distributed', { });
    const authorization = await got(client.authorizationUrl({ redirect_uri, response_type: 'code' }), noFollow);
    const params = client.callbackParams(authorization.headers.location);
    const tokens = await client.authorizationCallback(redirect_uri, params);
    const userinfo = await client.userinfo(tokens);
    const distributed = await client.fetchDistributedClaims(userinfo);
    assert(distributed.age);
  });
});
