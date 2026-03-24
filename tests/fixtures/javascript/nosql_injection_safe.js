// Safe: Extracting specific fields from user input
app.get('/users', (req, res) => {
    db.collection('users').find({ name: req.query.name, active: true });
});
