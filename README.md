# openid-client conformance tests

[![build][travis-image]][travis-url]

A conformance test suite for [openid-client] library certification of Basic RP, Implicit RP,
Hybrid RP, Dynamic RP and Config RP profiles.

Executes tests with expectations defined in [RP test tool][test-list] and downloads the log archive
for each of the tested profiles.

revision: March 2017


```
$ nvm use
$ npm install
...
$ npm run "basic" # or "id_token-implicit", "id_token+token-implicit", "code+id_token-hybrid", "code+token-hybrid", "code+id_token+token-hybrid", "config", "dynamic" or "non-profile"
...
```

[openid-client]: https://github.com/panva/node-openid-client
[test-list]: https://rp.certification.openid.net:8080/test_list
[travis-image]: https://travis-ci.com/panva/openid-client-conformance-tests.svg?branch=master
[travis-url]: https://travis-ci.com/panva/openid-client-conformance-tests/builds
