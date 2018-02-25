{
  "engines": {
    "composer": "^0.16.0"
  },
  "name": "degauth-network",
  "version": "0.2.0-20180102082548",
  "description": "Business Network to illustrate using Access Control over authenticated university degree.",
  "networkImage": "https://hyperledger.github.io/composer-sample-networks/packages/pii-network/networkimage.svg",
  "networkImageanimated": "https://hyperledger.github.io/composer-sample-networks/packages/pii-network/networkimageanimated.svg",
  "scripts": {
    "prepublish": "mkdirp ./dist && composer archive create  --sourceType dir --sourceName . -a ./dist/pii-network.bna",
    "pretest": "npm run lint",
    "lint": "eslint .",
    "postlint": "npm run licchk",
    "licchk": "license-check",
    "postlicchk": "npm run doc",
    "doc": "jsdoc --pedantic --recurse -c jsdoc.json",
    "test": "mocha -t 0 --recursive",
    "deploy": "./scripts/deploy.sh"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/hyperledger/composer-sample-networks.git"
  },
  "keywords": [
    "access control",
    "security",
    "composer",
    "composer-network"
  ],
  "author": "Hyperledger Composer",
  "license": "Apache-2.0",
  "devDependencies": {
    "chai": "^3.5.0",
    "composer-admin": "^0.16.0",
    "composer-cli": "^0.16.0",
    "composer-client": "^0.16.0",
    "composer-common": "^0.16.0",
    "composer-connector-embedded": "^0.16.0",
    "eslint": "^3.6.1",
    "istanbul": "^0.4.5",
    "jsdoc": "^3.5.5",
    "license-check": "^1.1.5",
    "mkdirp": "^0.5.1",
    "mocha": "^3.2.0",
    "moment": "^2.17.1"
  },
  "license-check-config": {
    "src": [
      "**/*.js",
      "!./coverage/**/*",
      "!./node_modules/**/*",
      "!./out/**/*",
      "!./scripts/**/*"
    ],
    "path": "header.txt",
    "blocking": true,
    "logInfo": false,
    "logError": true
  }
}