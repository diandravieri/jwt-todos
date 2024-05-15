const { body, validationResult } = require('express-validator');

async function runValidation(validations, data) {
  await Promise.all(validations.map(v => v.run({ body: data })));
  const errors = validationResult({ body: data });
  if (!errors.isEmpty()) {
    const errMsg = errors.array().map(error => ({ [error.param]: error.msg }));
    return errMsg;
  }
  return null;
}

module.exports = runValidation;