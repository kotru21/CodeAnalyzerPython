const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
});

app.post('/login', (req, res) => {
    pool.query('SELECT * FROM users WHERE name = $1', [req.body.username]);
});
