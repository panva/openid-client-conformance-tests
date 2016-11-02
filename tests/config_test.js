'use strict';

/* eslint-disable import/no-extraneous-dependencies, no-console, func-names, camelcase, no-unreachable, max-len, prefer-arrow-callback, no-restricted-syntax, guard-for-in */

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const assert = require('assert');
const { Issuer } = require('openid-client');
const got = require('got');
const nock = require('nock');
const timekeeper = require('timekeeper');

function reject() { throw new Error('expected a rejection'); }
const PROFILE = 'config';
const RP_ID = `${PROFILE}-node-openid-client`;
const redirect_uri = `https://${RP_ID}.dev/cb`;
const redirect_uris = [redirect_uri];
const GOT_OPTS = { followRedirect: false, retries: 0, timeout: 5000 };

describe(`RP Tests ${PROFILE} profile`, function () {
  afterEach(timekeeper.reset);
  afterEach(nock.cleanAll);
  afterEach(() => nock.enableNetConnect());

  this.timeout(10000);
  describe('Discovery', function () {
    it('rp-discovery-issuer-not-matching-config', async function () {
      const testId = 'rp-discovery-issuer-not-matching-config';
      try {
        await Issuer.webfinger(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);
        reject();
      } catch (err) {
        assert.equal(err.message, 'discovered issuer mismatch');
      }
    });

    it('rp-discovery-openid-configuration', async function () {
      const testId = 'rp-discovery-openid-configuration';
      const response = await got(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}/.well-known/openid-configuration`, GOT_OPTS);
      const discovery = JSON.parse(response.body);
      nock('https://rp.certification.openid.net:8080')
        .get(`/${RP_ID}/${testId}/.well-known/openid-configuration`)
        .reply(200, discovery);

      const ISSUER = await Issuer.discover(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);

      for (const property in discovery) {
        if (ISSUER.metadata[property]) {
          assert.deepEqual(discovery[property], ISSUER.metadata[property]);
        } else {
          console.warn('skipping property', property);
        }
      }
    });

    it('rp-discovery-jwks_uri-keys', async function () {
      const testId = 'rp-discovery-jwks_uri-keys';
      const ISSUER = await Issuer.discover(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);
      const jwks = await ISSUER.keystore();

      assert.equal(jwks.all().length, 4);
    });
  });

  describe('Key Rotation', function () {
    it('rp-key-rotation-op-sign-key', async function () {
      const testId = 'rp-key-rotation-op-sign-key';
      const ISSUER = await Issuer.discover(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);
      const CLIENT = await ISSUER.Client.register({ redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);
      const params = CLIENT.callbackParams(authorization.headers.location);
      await CLIENT.authorizationCallback(redirect_uri, params);

      timekeeper.travel(Date.now() + (61 * 1000)); // travel one minute from now, making the cached keystore stale

      const secondAuthorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);
      const secondParams = CLIENT.callbackParams(secondAuthorization.headers.location);
      await CLIENT.authorizationCallback(redirect_uri, secondParams);
    });
  });
});
