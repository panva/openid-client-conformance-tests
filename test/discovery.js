'use strict';

/* eslint-disable no-restricted-syntax */

const { Issuer } = require('openid-client');
const {
  discover,
  noFollow,
  reject,
  root,
  rpId,
} = require('./helper');

const assert = require('assert');
const got = require('got');
const nock = require('nock');

afterEach(nock.cleanAll);
afterEach(() => nock.enableNetConnect());

describe('Discovery', function () {
  it('rp-discovery-webfinger-url @dynamic', async function () {
    const testId = 'rp-discovery-webfinger-url';

    const issuer = await Issuer.webfinger(`${root}/${rpId}/${testId}/joe`);
    assert.equal(issuer.issuer, `${root}/${rpId}/${testId}`);
  });

  it('rp-discovery-webfinger-acct @dynamic', async function () {
    const testId = 'rp-discovery-webfinger-acct';

    const issuer = await Issuer.webfinger(`acct:${rpId}.${testId}@rp.certification.openid.net:8080`);
    assert.equal(issuer.issuer, `${root}/${rpId}/${testId}`);
  });

  it('rp-discovery-issuer-not-matching-config @config,@dynamic', async function () {
    try {
      await Issuer.webfinger(`${root}/${rpId}/rp-discovery-issuer-not-matching-config`);
      reject();
    } catch (err) {
      assert.equal(err.message, 'discovered issuer mismatch');
    }
  });

  it('rp-discovery-openid-configuration @config,@dynamic', async function () {
    const testId = 'rp-discovery-openid-configuration';
    const response = await got(`${root}/${rpId}/${testId}/.well-known/openid-configuration`, noFollow);
    const discovery = JSON.parse(response.body);
    nock(root)
      .get(`/${rpId}/${testId}/.well-known/openid-configuration`)
      .reply(200, discovery);

    const issuer = await discover(testId);

    for (const property in discovery) {
      if (issuer.metadata[property]) {
        assert.deepEqual(discovery[property], issuer.metadata[property]);
      }
    }
  });

  it('rp-discovery-jwks_uri-keys @config,@dynamic', async function () {
    const issuer = await discover('rp-discovery-jwks_uri-keys');
    const jwks = await issuer.keystore();

    assert.equal(jwks.all().length, 4);
  });
});
