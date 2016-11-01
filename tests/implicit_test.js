'use strict';

/* eslint-disable import/no-extraneous-dependencies, no-console, func-names, camelcase, no-unreachable, max-len, prefer-arrow-callback */

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const assert = require('assert');
const { Issuer } = require('openid-client');
const got = require('got');

function reject() { throw new Error('expected a rejection'); }
const PROFILE = 'implicit';
const RP_ID = `${PROFILE}-node-openid-client`;
const redirect_uri = `https://${RP_ID}.dev/cb`;
const redirect_uris = [redirect_uri];
const GOT_OPTS = { followRedirect: false, retries: 0, timeout: 5000 };

async function register(rpId, testId, metadata) {
  const issuer = await Issuer.discover(`https://rp.certification.openid.net:8080/${rpId}/${testId}`);
  const client = await issuer.Client.register(metadata);
  return { ISSUER: issuer, CLIENT: client };
}

describe(`RP Tests ${PROFILE} profile`, function () {
  this.timeout(10000);
  describe('Response Type and Response Mode', function () {
    it('rp-response_type-id_token', async function () {
      const testId = 'rp-response_type-id_token';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, response_type: 'id_token', nonce: String(Math.random()) }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      assert(params.id_token);
    });

    it('rp-response_type-id_token+token', async function () {
      const testId = 'rp-response_type-id_token+token';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, response_type: 'id_token token', nonce: String(Math.random()) }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      assert(params.id_token);
      assert(params.access_token);
    });
  });

  describe('nonce Request Parameter', function () {
    it('rp-nonce-unless-code-flow', async function () {
      const testId = 'rp-nonce-unless-code-flow';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      try {
        CLIENT.authorizationUrl({ redirect_uri, response_type: 'id_token' });
        reject();
      } catch (err) {
        assert.equal(err.message, 'nonce MUST be provided for implicit and hybrid flows');
      }
      const authorization = await got(CLIENT.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
      assert(tokens);
    });

    it('rp-nonce-invalid', async function () {
      const testId = 'rp-nonce-invalid';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, response_type: 'id_token', nonce }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'nonce mismatch');
      }
    });
  });

  describe('Client Authentication', function () {
    it.skip('rp-token_endpoint-client_secret_basic');
  });

  describe('ID Token', function () {
    it('rp-id_token-bad-sig-rs256', async function () { // optional
      const testId = 'rp-id_token-bad-sig-rs256';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'invalid signature');
      }
    });

    it('rp-id_token-bad-at_hash', async function () { // optional
      const testId = 'rp-id_token-bad-at_hash';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'at_hash mismatch');
      }
    });

    it('rp-id_token-issuer-mismatch', async function () {
      const testId = 'rp-id_token-issuer-mismatch';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'unexpected iss value');
      }
    });

    it('rp-id_token-iat', async function () {
      const testId = 'rp-id_token-iat';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property iat');
      }
    });

    it('rp-id_token-aud', async function () {
      const testId = 'rp-id_token-aud';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'aud is missing the client_id');
      }
    });

    it.skip('rp-id_token-sub', async function () { // does not allow other than code response_types;
      const testId = 'rp-id_token-sub';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property sub');
      }
    });

    it('rp-id_token-kid-absent-single-jwks', async function () { // optional
      const testId = 'rp-id_token-kid-absent-single-jwks';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
    });

    it('rp-id_token-kid-absent-multiple-jwks', async function () { // optional
      const testId = 'rp-id_token-kid-absent-multiple-jwks';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce, response_type: 'id_token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'multiple matching keys, kid must be provided');
      }
    });
  });

  describe('UserInfo Endpoint', function () {
    it('rp-userinfo-bearer-header', async function () {
      const testId = 'rp-userinfo-bearer-header';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
      await CLIENT.userinfo(tokens, { via: 'header' });
    });

    it('rp-userinfo-bearer-body', async function () {
      const testId = 'rp-userinfo-bearer-body';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
      await CLIENT.userinfo(tokens, { via: 'body', verb: 'post' });
    });

    it('rp-userinfo-bad-sub-claim', async function () {
      const testId = 'rp-userinfo-bad-sub-claim';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris, response_types: ['id_token token'], grant_types: ['implicit'] });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ nonce, redirect_uri, response_type: 'id_token token' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location.replace('#', '?'));
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
      try {
        await CLIENT.userinfo(tokens);
        reject();
      } catch (err) {
        assert.equal(err.message, 'userinfo sub mismatch');
      }
    });
  });
});
