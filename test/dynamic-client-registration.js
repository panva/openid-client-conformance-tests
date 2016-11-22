'use strict';

const { Issuer } = require('openid-client');
const {
  redirect_uris,
  root,
  rpId,
} = require('./helper');

const assert = require('assert');

describe('Dynamic Client Registration', function () {
  it('rp-registration-dynamic @dynamic', async function () {
    const issuer = await Issuer.discover(`${root}/${rpId}/rp-key-rotation-op-sign-key`);
    const client = await issuer.Client.register({ redirect_uris });

    assert.equal(client.issuer, issuer);
  });
});
