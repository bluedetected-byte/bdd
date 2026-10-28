'use strict';

const serverless = require('serverless-http');
const { app, init } = require('../../server.js');

let initPromise;
const handler = serverless(app);

exports.handler = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;
  if (!initPromise) {
    initPromise = init().catch((error) => {
      initPromise = null;
      throw error;
    });
  }
  await initPromise;
  return handler(event, context);
};
