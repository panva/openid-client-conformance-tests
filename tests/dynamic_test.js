'use strict';

/* eslint-disable import/no-extraneous-dependencies, no-console, func-names, camelcase, no-unreachable, max-len, prefer-arrow-callback, no-restricted-syntax, guard-for-in */

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const GitHub = require('github-api');

const gh = new GitHub({
  token: process.env.GH_TOKEN,
});
const gist = gh.getGist('e2692453a1a8b3a6db46a5b42603fba7');
// const JWKS_URI = 'https://rawgit.com/panva/e2692453a1a8b3a6db46a5b42603fba7/raw/jwks.json';
const JWKS_URI = 'https://gist.githubusercontent.com/panva/e2692453a1a8b3a6db46a5b42603fba7/raw/jwks.json';
const REQUEST = 'https://gist.githubusercontent.com/panva/e2692453a1a8b3a6db46a5b42603fba7/raw/request.jwt';

const jose = require('node-jose');
const assert = require('assert');
const { Issuer } = require('openid-client');
const got = require('got');
const timekeeper = require('timekeeper');

function reject() { throw new Error('expected a rejection'); }
const PROFILE = 'dynamic';
const RP_ID = `${PROFILE}-node-openid-client`;
const redirect_uri = `https://${RP_ID}.dev/cb`;
const redirect_uris = [redirect_uri];
const GOT_OPTS = { followRedirect: false, retries: 0, timeout: 5000 };

describe(`RP Tests ${PROFILE} profile`, function () {
  afterEach(timekeeper.reset);
  this.timeout(10000);
  describe('Discovery', function () {
    it('rp-discovery-webfinger-url', async function () {
      const testId = 'rp-discovery-webfinger-url';

      const issuer = await Issuer.webfinger(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}/joe`);
      assert.equal(issuer.issuer, `https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);
    });

    it('rp-discovery-webfinger-acct', async function () {
      const testId = 'rp-discovery-webfinger-acct';

      const issuer = await Issuer.webfinger(`acct:${RP_ID}.${testId}@rp.certification.openid.net:8080`);
      assert.equal(issuer.issuer, `https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);
    });

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

  describe('Dynamic Client Registration', function () {
    it('rp-registration-dynamic', async function () {
      const testId = 'rp-key-rotation-op-sign-key';
      const ISSUER = await Issuer.discover(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);
      const CLIENT = await ISSUER.Client.register({ redirect_uris });

      assert.equal(CLIENT.issuer, ISSUER);
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

    it('rp-key-rotation-rp-sign-key', async function () {
      const testId = 'rp-key-rotation-rp-sign-key';
      const ISSUER = await Issuer.discover(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);

      const keystore = jose.JWK.createKeyStore();

      await keystore.generate('RSA', 1024);
      let ref = await jose.JWS.createSign({ fields: { alg: 'RS256', typ: 'JWT' }, format: 'compact' }, { key: keystore.get() })
        .update(JSON.stringify({ redirect_uri })).final();

      await gist.update({
        files: {
          'jwks.json': { content: JSON.stringify(keystore.toJSON()) },
          'request.jwt': { content: ref },
        },
      });

      keystore.remove(keystore.get());

      const CLIENT = await ISSUER.Client.register({ redirect_uris, request_object_signing_alg: 'RS256', jwks_uri: JWKS_URI });

      await got(CLIENT.authorizationUrl({ redirect_uri, request_uri: `${REQUEST}#${Math.random()}` }), GOT_OPTS);

      await keystore.generate('RSA', 1024);
      ref = await jose.JWS.createSign({ fields: { alg: 'RS256', typ: 'JWT' }, format: 'compact' }, { key: keystore.get() })
        .update(JSON.stringify({ redirect_uri })).final();

      await gist.update({
        files: {
          'jwks.json': { content: JSON.stringify(keystore.toJSON()) },
          'request.jwt': { content: ref },
        },
      });

      await got(CLIENT.authorizationUrl({ redirect_uri, request_uri: `${REQUEST}#${Math.random()}` }), GOT_OPTS);
    });
  });
});
