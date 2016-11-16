'use strict';

/* eslint-disable func-names, prefer-arrow-callback, no-restricted-syntax, guard-for-in, no-console, max-len */

const { Issuer } = require('openid-client');
const {
  clear,
  download,
  noFollow,
  redirect_uri,
  redirect_uris,
  reject,
  root,
  rpId,
} = require('./test_helper')('dynamic');

const assert = require('assert');
const got = require('got');
const nock = require('nock');
const timekeeper = require('timekeeper');

describe('RP Tests DYNAMIC profile', function () {
  afterEach(timekeeper.reset);
  afterEach(nock.cleanAll);
  afterEach(() => nock.enableNetConnect());

  before(clear);
  after(download);

  this.timeout(10000);
  describe('Discovery', function () {
    it('rp-discovery-webfinger-url', async function () {
      const testId = 'rp-discovery-webfinger-url';

      const issuer = await Issuer.webfinger(`${root}/${rpId}/${testId}/joe`);
      assert.equal(issuer.issuer, `${root}/${rpId}/${testId}`);
    });

    it('rp-discovery-webfinger-acct', async function () {
      const testId = 'rp-discovery-webfinger-acct';

      const issuer = await Issuer.webfinger(`acct:${rpId}.${testId}@rp.certification.openid.net:8080`);
      assert.equal(issuer.issuer, `${root}/${rpId}/${testId}`);
    });

    it('rp-discovery-issuer-not-matching-config', async function () {
      const testId = 'rp-discovery-issuer-not-matching-config';
      try {
        await Issuer.webfinger(`${root}/${rpId}/${testId}`);
        reject();
      } catch (err) {
        assert.equal(err.message, 'discovered issuer mismatch');
      }
    });

    it('rp-discovery-openid-configuration', async function () {
      const testId = 'rp-discovery-openid-configuration';
      const response = await got(`${root}/${rpId}/${testId}/.well-known/openid-configuration`, noFollow);
      const discovery = JSON.parse(response.body);
      nock(root)
        .get(`/${rpId}/${testId}/.well-known/openid-configuration`)
        .reply(200, discovery);

      const issuer = await Issuer.discover(`${root}/${rpId}/${testId}`);

      for (const property in discovery) {
        if (issuer.metadata[property]) {
          assert.deepEqual(discovery[property], issuer.metadata[property]);
        } else {
          console.warn('skipping property', property);
        }
      }
    });

    it('rp-discovery-jwks_uri-keys', async function () {
      const testId = 'rp-discovery-jwks_uri-keys';
      const issuer = await Issuer.discover(`${root}/${rpId}/${testId}`);
      const jwks = await issuer.keystore();

      assert.equal(jwks.all().length, 4);
    });
  });

  describe('Dynamic Client Registration', function () {
    it('rp-registration-dynamic', async function () {
      const testId = 'rp-key-rotation-op-sign-key';
      const issuer = await Issuer.discover(`${root}/${rpId}/${testId}`);
      const client = await issuer.Client.register({ redirect_uris });

      assert.equal(client.issuer, issuer);
    });
  });

  describe('Key Rotation', function () {
    it('rp-key-rotation-op-sign-key', async function () {
      const testId = 'rp-key-rotation-op-sign-key';
      const issuer = await Issuer.discover(`${root}/${rpId}/${testId}`);
      const client = await issuer.Client.register({ redirect_uris });
      const authorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);
      const params = client.callbackParams(authorization.headers.location);
      await client.authorizationCallback(redirect_uri, params);

      timekeeper.travel(Date.now() + (61 * 1000)); // travel one minute from now, making the cached keystore stale

      const secondAuthorization = await got(client.authorizationUrl({ redirect_uri }), noFollow);
      const secondParams = client.callbackParams(secondAuthorization.headers.location);
      await client.authorizationCallback(redirect_uri, secondParams);
    });
  });
});
