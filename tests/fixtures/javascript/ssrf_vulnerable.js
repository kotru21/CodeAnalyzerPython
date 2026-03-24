// Vulnerable: fetch with user-controlled URL
app.get('/proxy', async (req, res) => {
    const response = await fetch(req.query.url);
    const data = await response.text();
    res.send(data);
});

// Vulnerable: axios.get with user-controlled URL
app.post('/webhook', async (req, res) => {
    const result = await axios.get(req.body.callback_url);
    res.json(result.data);
});
