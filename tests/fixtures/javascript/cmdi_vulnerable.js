const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/run', (req, res) => {
    exec(`ls ${req.query.dir}`);
});

app.post('/calc', (req, res) => {
    const expr = req.body.expression;
    eval(expr);
});
