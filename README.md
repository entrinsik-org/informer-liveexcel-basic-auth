# informer-liveexcel-basic-auth
Patches pre 5.4 versions basic auth scheme for live excel, to enabled LDAP and other username / password domain strategies

## Installation

```
npm install @entrinsik/informer-liveexcel-basic-auth
```

then add to config.json

```
"plugins" : {
    "@entrinsik/informer-liveexcel-basic-auth" : {}
  }
```

## Usage

This will only authenticate existing users for a login domain that has a login form post with

req.body.username

req.body.password

which includes all ldap and active directory domains, as well as most bespoke domains