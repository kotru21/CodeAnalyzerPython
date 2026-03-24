// Vulnerable: Redirect with user-controlled URL from query
app.get('/redirect', (req, res) => {
    res.redirect(req.query.url);
});

// Vulnerable: Redirect with user-controlled URL from params
app.get('/go/:target', (req, res) => {
    res.redirect(req.params.target);
});
