'use strict';

/** An error that is safe to show to the user (status + short message). */
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

module.exports = { HttpError };
