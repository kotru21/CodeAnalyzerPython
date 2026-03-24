// Vulnerable: MD5 hashing
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// Vulnerable: Math.random for token generation
function generateToken() {
    return Math.random().toString(36).substr(2);
}
