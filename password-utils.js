const crypto = require('crypto');

function hashPassword(password) {
  const randomString = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, randomString, 100000, 64, 'sha512').toString('hex');
  return randomString + ':' + hash;
}

function verifyPassword(password, storedHash) {
  const parts = storedHash.split(':');
  const secretAddon = parts[0];
  const originalHash = parts[1];
  
  const newHash = crypto.pbkdf2Sync(password, secretAddon, 100000, 64, 'sha512').toString('hex');
  
  return newHash === originalHash;
}

module.exports = { hashPassword, verifyPassword };