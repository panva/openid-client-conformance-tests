'use strict';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const { Issuer } = require('openid-client');
const got = require('got');
const fs = require('fs');

const rpId = 'node-openid-client';
const root = 'https://rp.certification.openid.net:8080';
const redirectUri = `https://${rpId}.dev/cb`;

module.exports = function bootstrap(profile) {
  return {
    noFollow: { followRedirect: false },
    root,
    rpId,
    clear() {
      return got(`${root}/clear/${rpId}`);
    },
    download() {
      return got(`${root}/mktar/${rpId}`).then(response => fs.writeFileSync(`${profile}-${rpId}.tar`, response.body));
    },
    redirect_uri: redirectUri,
    redirect_uris: [redirectUri],
    async register(testId, metadata) {
      const issuer = await Issuer.discover(`${root}/${rpId}/${testId}`);
      const client = await issuer.Client.register(metadata);
      return { issuer, client };
    },
    reject() { throw new Error('expected a rejection'); },
  };
};
