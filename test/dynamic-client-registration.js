const { strict: assert } = require('assert');

const {
  register,
  describe,
  it,
} = require('./helper');

describe('Dynamic Client Registration', function () {
  it('rp-registration-dynamic @code-dynamic', async function () {
    const { client, issuer } = await register('rp-registration-dynamic', { });
    assert.equal(client.issuer, issuer);
  });
});
