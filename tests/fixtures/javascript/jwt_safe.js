const jsonwebtoken = require('jsonwebtoken');

app.post('/login', (req, res) => {
    const token = jsonwebtoken.sign({ userId: req.body.id }, 'secret', { algorithm: 'HS256' });
    res.json({ token });
});
