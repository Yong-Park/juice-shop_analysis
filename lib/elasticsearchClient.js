const { Client } = require('@elastic/elasticsearch');
const config = require('../config/elasticConfig');

const client = new Client({
  node: config.node,
  auth: config.auth
});

module.exports = client;
