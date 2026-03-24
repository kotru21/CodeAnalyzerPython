// Vulnerable: RegExp constructed from user input
app.post('/search', (req, res) => {
    const pattern = new RegExp(req.body.pattern);
    const match = pattern.test(data);
});
