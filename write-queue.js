'use strict';

function createWriteQueue(maxPending) {
  if (!Number.isSafeInteger(maxPending) || maxPending < 1) {
    throw new TypeError('maxPending must be a positive safe integer.');
  }

  let tail = Promise.resolve();
  let pending = 0;

  return function enqueue(operation) {
    if (pending >= maxPending) {
      const error = new Error('The service is busy. Please retry shortly.');
      error.status = 503;
      error.retryAfter = 1;
      return Promise.reject(error);
    }

    pending += 1;
    const result = tail.then(operation);
    tail = result.catch(() => {});
    return result.finally(() => {
      pending -= 1;
    });
  };
}

module.exports = { createWriteQueue };
