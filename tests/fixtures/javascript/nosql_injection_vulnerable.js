// Vulnerable: Passing req.body directly to MongoDB find
app.post('/users/search', (req, res) => {
    db.collection('users').find(req.body);
});

// Vulnerable: Using $where operator with user input
app.get('/users', (req, res) => {
    db.collection('users').find({ $where: req.query.filter });
});
