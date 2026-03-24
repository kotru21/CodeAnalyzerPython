// Safe: Static redirect path
app.get('/home', (req, res) => {
    res.redirect('/dashboard');
});
