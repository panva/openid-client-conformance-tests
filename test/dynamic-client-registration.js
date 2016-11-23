'use strict';

const {
  register,
} = require('./helper');

const assert = require('assert');

describe('Dynamic Client Registration', function () {
  it('rp-registration-dynamic @dynamic', async function () {
    const { client, issuer } = await register('rp-registration-dynamic', { });
    assert.equal(client.issuer, issuer);
  });
});
