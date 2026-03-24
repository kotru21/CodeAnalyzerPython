// Safe: Static file path
const fs = require('fs');
const data = fs.readFileSync('./config/settings.json', 'utf8');
