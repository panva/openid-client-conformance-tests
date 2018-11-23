'use strict';

/* eslint-disable no-console */

const { Issuer } = require('openid-client');
const path = require('path');
const fse = require('fs-extra');
const fs = require('fs');
const tar = require('tar');
const got = require('got');
const url = require('url');
const timekeeper = require('timekeeper');

let rpId = 'node-openid-client';
const echo = 'https://limitless-retreat-96294.herokuapp.com';
const root = process.env.ISSUER || 'https://rp.certification.openid.net:8080';
const redirectUri = `https://${rpId}.dev/cb`;

const [responseType, profile] = (() => {
  const last = process.argv[process.argv.length - 1];
  if (last.startsWith('@')) {
    return last.slice(1).split('-');
  }
  return [];
})();

if (responseType && profile) {
  rpId = `${rpId}-${profile}-${responseType}`;
}

async function syncTime() {
  const { headers: { date } } = await got.head(root);
  timekeeper.travel(new Date(date));
}

before(syncTime);

before(async function () {
  const logIndex = await got(`${root}/log/${rpId}`);
  if (/Clear all test logs/.exec(logIndex.body)) {
    console.log('Clearing logs');
    await got(`${root}/clear/${rpId}`);
    console.log('Clearing logs - DONE');
  }
});

before(function kickstartEcho() {
  return got.get(echo).then(() => {}, () => {});
});

Issuer.defaultHttpOptions = { timeout: 5000 };

if (profile) {
  const profileFolder = path.resolve('logs', profile);
  fse.emptyDirSync(`${profileFolder}/${responseType}`);
  after(async function () {
    const logIndex = await got(`${root}/log/${rpId}`);
    if (/Download tar file/.exec(logIndex.body)) {
      await new Promise((resolve, reject) => {
        console.log('Downloading logs');
        got.stream(`${root}/mktar/${rpId}`)
          .pipe(tar.Extract({
            path: profileFolder,
          }))
          .on('close', () => {
            fse.move(`${profileFolder}/${rpId}`, `${profileFolder}/${responseType}`, {
              clobber: true,
            }, (err) => {
              if (err) {
                reject();
              } else {
                resolve();
              }
            });
          })
          .on('error', reject);
      });
    }
  });
}

let testId;
global.log = function () {};

function myIt(...args) {
  if (args[0].startsWith('rp-')) testId = args[0];
  const localTestId = testId.includes(' ') ? testId.substring(0, testId.indexOf(' ')) : testId;
  if (args[1]) {
    it(args[0], async function () {
      if (profile) {
        const profileFolder = path.resolve('logs', profile);
        const rpFolder = `${profileFolder}/${rpId}`;
        const logFile = `${rpFolder}/${localTestId}.log`;
        fse.createFileSync(logFile);
        fs.appendFileSync(logFile, `${new Date().toISOString()} ${localTestId} test definition\n`);
        fs.appendFileSync(logFile, `  ${args[1]}\n`);
        fs.appendFileSync(logFile, `${new Date().toISOString()} executing\n\n`);
        global.log = function (...logargs) {
          logargs.unshift(new Date().toISOString());
          logargs.push('\n');
          fs.appendFileSync(logFile, logargs.join(' '));
        };
      }
      try {
        await args[1].call(this);
      } catch (err) {
        log('test failed, message:', err.message);
        throw err;
      }
      log('test finished, OK');
    });
  } else {
    it(args[0]);
  }
}
myIt.skip = it.skip;
myIt.only = it.only;

function myDescribe(...args) {
  if (args[0].startsWith('rp-')) testId = args[0];
  describe.apply(this, args);
}
myDescribe.skip = describe.skip;
myDescribe.only = describe.only;

module.exports = {
  noFollow: { followRedirect: false },
  root,
  it: myIt,
  describe: myDescribe,
  rpId,
  syncTime,
  redirect_uri: redirectUri,
  redirect_uris: [redirectUri],
  async authorizationCallback(client, ...params) {
    try {
      const res = await client.authorizationCallback(...params);
      log('authentication callback succeeded', JSON.stringify(res, null, 4));
      return res;
    } catch (err) {
      log('authentication callback failed', err);
      throw err;
    }
  },
  async userinfoCall(client, ...params) {
    try {
      const res = await client.userinfo(...params);
      log('userinfo response', JSON.stringify(res, null, 4));
      return res;
    } catch (err) {
      log('userinfo failed', err);
      throw err;
    }
  },
  async authorize(...params) {
    const { pathname, query } = url.parse(params[0], true);
    log('authentication request to', pathname);
    log('authentication request parameters', JSON.stringify(query, null, 4));
    const response = await got(...params);
    const { query: callback } = url.parse(response.headers.location.replace('#', '?'), true);
    log('authentication response', JSON.stringify(callback, null, 4));
    return response;
  },
  async discover(test) {
    const issuer = await Issuer.discover(`${root}/${rpId}/${test}`);
    log('discovered', issuer.issuer);
    return issuer;
  },
  async register(test, metadata, keystore) {
    const issuer = await Issuer.discover(`${root}/${rpId}/${test}`);
    log('discovered', issuer.issuer);

    const properties = Object.assign({
      client_name: Issuer.defaultHttpOptions.headers['User-Agent'],
      redirect_uris: [redirectUri],
      contacts: ['dummy@dummy.org'],
      response_types: responseType ? [responseType.replace(/\+/g, ' ')] : ['code', 'id_token', 'code token', 'code id_token', 'id_token token', 'code id_token token', 'none'],
      grant_types: responseType && responseType.indexOf('token') === -1 ? ['authorization_code'] : ['implicit', 'authorization_code'],
    }, metadata);

    log('registering client', JSON.stringify(properties, null, 4));
    const client = await issuer.Client.register(properties, { keystore });
    log('registered client', client.client_id, JSON.stringify(client.metadata, null, 4));
    client.CLOCK_TOLERANCE = 5;
    return { issuer, client };
  },
  reject() { throw new Error('expected a rejection'); },
  async gist(content) {
    await got.post(echo, { body: { echo: content } });
    return `${echo}/${Date.now()}`;
  },
};
