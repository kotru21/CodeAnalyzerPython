app.get('/session', (req, res) => {
    res.cookie('sessionId', req.query.id, { httpOnly: false, secure: true });
});
