// Safe: SHA-256 hashing and crypto.randomUUID
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update(data).digest('hex');
const id = crypto.randomUUID();
