'use strict';

/* eslint-disable import/no-extraneous-dependencies, no-console, func-names, camelcase, no-unreachable, max-len, prefer-arrow-callback */

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const assert = require('assert');
const { Issuer } = require('openid-client');
const got = require('got');

function reject() { throw new Error('expected a rejection'); }
const PROFILE = 'basic';
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
    it('rp-response_type-code', async function () {
      const { CLIENT } = await register(RP_ID, 'rp-response_type-code', { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);
      const params = CLIENT.callbackParams(authorization.headers.location);
      assert(params.code);
    });
  });

  describe('scope Request Parameter', function () {
    it('rp-scope-userinfo-claims', async function () { // optional
      const testId = 'rp-scope-userinfo-claims';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, scope: 'openid email' }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params);
      const userinfo = await CLIENT.userinfo(tokens);
      assert(userinfo.email);
    });
  });

  describe('nonce Request Parameter', function () {
    it('rp-nonce-invalid', async function () {
      const testId = 'rp-nonce-invalid';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const nonce = String(Math.random());
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri, nonce }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      try {
        await CLIENT.authorizationCallback(redirect_uri, params, { nonce });
        reject();
      } catch (err) {
        assert.equal(err.message, 'nonce mismatch');
      }
    });
  });

  describe('Client Authentication', function () {
    it('rp-token_endpoint-client_secret_basic', async function () {
      const testId = 'rp-token_endpoint-client_secret_basic';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params);
      assert(tokens);
    });
  });

  describe('ID Token', function () {
    it('rp-id_token-bad-sig-rs256', async function () { // optional
      const testId = 'rp-id_token-bad-sig-rs256';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      try {
        await CLIENT.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'invalid signature');
      }
    });

    it('rp-id_token-sig-none', async function () { // optional
      const testId = 'rp-id_token-sig-none';
      const ISSUER = await Issuer.discover(`https://rp.certification.openid.net:8080/${RP_ID}/${testId}`);
      const CLIENT = await ISSUER.Client.register({ redirect_uris, id_token_signed_response_alg: 'none' });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params);
      assert(tokens.id_token);
    });

    it('rp-id_token-issuer-mismatch', async function () {
      const testId = 'rp-id_token-issuer-mismatch';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      try {
        await CLIENT.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'unexpected iss value');
      }
    });

    it('rp-id_token-iat', async function () {
      const testId = 'rp-id_token-iat';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      try {
        await CLIENT.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property iat');
      }
    });

    it('rp-id_token-aud', async function () {
      const testId = 'rp-id_token-aud';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      try {
        await CLIENT.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'aud is missing the client_id');
      }
    });

    it('rp-id_token-sub', async function () {
      const testId = 'rp-id_token-sub';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      try {
        await CLIENT.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'missing required JWT property sub');
      }
    });

    it('rp-id_token-kid-absent-single-jwks', async function () { // optional
      const testId = 'rp-id_token-kid-absent-single-jwks';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      await CLIENT.authorizationCallback(redirect_uri, params);
    });

    it('rp-id_token-kid-absent-multiple-jwks', async function () { // optional
      const testId = 'rp-id_token-kid-absent-multiple-jwks';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      try {
        await CLIENT.authorizationCallback(redirect_uri, params);
        reject();
      } catch (err) {
        assert.equal(err.message, 'multiple matching keys, kid must be provided');
      }
    });
  });

  describe('UserInfo Endpoint', function () {
    it('rp-userinfo-bearer-header', async function () {
      const testId = 'rp-userinfo-bearer-header';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params);
      await CLIENT.userinfo(tokens, { via: 'header' });
    });

    it('rp-userinfo-bearer-body', async function () {
      const testId = 'rp-userinfo-bearer-body';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params);
      await CLIENT.userinfo(tokens, { via: 'body', verb: 'post' });
    });

    it('rp-userinfo-bad-sub-claim', async function () {
      const testId = 'rp-userinfo-bad-sub-claim';
      const { CLIENT } = await register(RP_ID, testId, { redirect_uris });
      const authorization = await got(CLIENT.authorizationUrl({ redirect_uri }), GOT_OPTS);

      const params = CLIENT.callbackParams(authorization.headers.location);
      const tokens = await CLIENT.authorizationCallback(redirect_uri, params);
      try {
        await CLIENT.userinfo(tokens);
        reject();
      } catch (err) {
        assert.equal(err.message, 'userinfo sub mismatch');
      }
    });
  });
});
