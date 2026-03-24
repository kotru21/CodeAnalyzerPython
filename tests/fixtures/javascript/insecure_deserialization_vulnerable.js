// Vulnerable: node-serialize unserialize
const serialize = require('node-serialize');
app.post('/data', (req, res) => {
    const obj = serialize.unserialize(req.body.data);
    res.json(obj);
});

// Vulnerable: eval with Buffer.from decoded data
const payload = Buffer.from(req.body.encoded, 'base64').toString();
eval(payload);
