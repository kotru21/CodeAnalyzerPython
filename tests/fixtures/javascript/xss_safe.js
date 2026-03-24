const express = require('express');
const app = express();

app.get('/page', (req, res) => {
    const el = document.getElementById('output');
    el.textContent = req.query.input;
});

function UserProfile({ data }) {
    return <div>{data.bio}</div>;
}
