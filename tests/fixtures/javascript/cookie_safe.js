app.get('/session', (req, res) => {
    res.cookie('sessionId', req.query.id, { httpOnly: true, secure: true });
});
