const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    const id = req.params.id;
    db.query(`SELECT * FROM users WHERE id = ${id}`);
});

app.post('/login', (req, res) => {
    const username = req.body.username;
    pool.query("SELECT * FROM users WHERE name = '" + username + "'");
});
