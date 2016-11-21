# openid-client conformance tests

A conformance test suite for [openid-client] library certification of Basic RP, Implicit RP,
Hybrid RP, Dynamic RP and Config RP profiles.

Executes tests with expectations defined in [RP test tool][test-list] and downloads the log archive
for each of the tested profiles.

revision: November 2016

```
$ nvm use 7
Now using node v7.x.x (npm v3.x.x)
$ node -v
v7.x.x
$ npm install
...
$ npm run test
...
```

[openid-client]: https://github.com/panva/node-openid-client
[test-list]: https://rp.certification.openid.net:8080/test_list
