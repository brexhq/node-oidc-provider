const { JWK: { createKeyStore, asKeyStore, asKey } } = require('node-jose');

const Provider = require('./provider');
const AdapterTest = require('./adapter_test');
const errors = require('./helpers/errors');

module.exports = {
  Provider,
  AdapterTest,
  createKeyStore,
  asKeyStore,
  asKey,
  errors,

  default: Provider,
};
