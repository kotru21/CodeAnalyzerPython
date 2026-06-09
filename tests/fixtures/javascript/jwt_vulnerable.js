const jwt = require('jsonwebtoken');

app.post('/login', (req, res) => {
    const token = jwt.sign({ userId: req.body.id }, 'secret', { algorithm: 'none' });
    res.json({ token });
});
