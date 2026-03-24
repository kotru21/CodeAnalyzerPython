const express = require('express');
const app = express();

app.get('/page', (req, res) => {
    const el = document.getElementById('output');
    el.innerHTML = req.query.input;
});

app.get('/render', (req, res) => {
    document.write(req.query.html);
});

function UserProfile({ data }) {
    return <div dangerouslySetInnerHTML={{__html: data.bio}} />;
}
