/* eslint-disable no-restricted-syntax */

const url = require('url');
const { Issuer } = require('openid-client');

const { strict: assert } = require('assert');
const got = require('got');
const nock = require('nock');
const {
  discover,
  noFollow,
  reject,
  root,
  rpId,
  describe,
  it,
} = require('./helper');

afterEach(nock.cleanAll);
afterEach(() => nock.enableNetConnect());

describe('Discovery', function () {
  it('rp-discovery-webfinger-url @code-dynamic', async function () {
    const testId = 'rp-discovery-webfinger-url';
    const input = `${root}/${rpId}/${testId}/joe`;
    const issuer = await Issuer.webfinger(input);
    log('webfinger using', input, 'discovered', issuer.issuer, JSON.stringify(issuer, null, 4));
    assert.equal(issuer.issuer, `${root}/${rpId}/${testId}`);
  });

  it('rp-discovery-webfinger-acct @code-dynamic', async function () {
    const testId = 'rp-discovery-webfinger-acct';
    const input = `acct:${rpId}.${testId}@${url.parse(root).host}`;
    const issuer = await Issuer.webfinger(input);
    log('webfinger using', input, 'discovered', issuer.issuer, JSON.stringify(issuer, null, 4));
    assert.equal(issuer.issuer, `${root}/${rpId}/${testId}`);
  });

  it('rp-discovery-issuer-not-matching-config @code-config,@code-dynamic', async function () {
    try {
      const input = `${root}/${rpId}/rp-discovery-issuer-not-matching-config`;
      log('webfinger discovery', input);
      await Issuer.webfinger(input);
      reject();
    } catch (err) {
      log('caught', err);
      assert.equal(err.message, `discovered issuer mismatch, expected ${root}/${rpId}/rp-discovery-issuer-not-matching-config, got: https://example.com`);
    }
  });

  it('rp-discovery-openid-configuration @code-config,@code-dynamic', async function () {
    const testId = 'rp-discovery-openid-configuration';
    const response = await got(`${root}/${rpId}/${testId}/.well-known/openid-configuration`, noFollow);
    const discovery = JSON.parse(response.body);
    nock(root)
      .get(`/${rpId}/${testId}/.well-known/openid-configuration`)
      .reply(200, discovery);

    const issuer = await discover(testId);

    for (const property in discovery) {
      if (issuer.metadata[property]) {
        log('expecting property', property, 'of value', issuer.metadata[property], 'got', discovery[property]);
        assert.deepEqual(discovery[property], issuer.metadata[property]);
      }
    }
  });

  it('rp-discovery-jwks_uri-keys @code-config,@code-dynamic', async function () {
    const issuer = await discover('rp-discovery-jwks_uri-keys');
    const jwks = await issuer.keystore();

    assert.equal(jwks.all().length, 4);
    log('fetched jwks_uri', JSON.stringify(jwks.toJWKS(), null, 4));
  });

  it('rp-discovery-webfinger-unknown-member', async function () {
    const testId = 'rp-discovery-webfinger-unknown-member';
    const input = `${root}/${rpId}/${testId}`;
    const issuer = await Issuer.webfinger(input);
    assert(issuer);
  });

  it('rp-discovery-webfinger-http-href', async function () {
    const testId = 'rp-discovery-webfinger-http-href';
    const input = `${root}/${rpId}/${testId}`;
    try {
      await Issuer.webfinger(input);
      reject();
    } catch (err) {
      log('caught', err);
      assert.equal(err.message, `invalid issuer location ${root.replace('https:', 'http:')}/${rpId}/rp-discovery-webfinger-http-href`);
    }
  });
});
