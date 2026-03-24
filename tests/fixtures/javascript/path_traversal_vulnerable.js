// Vulnerable: readFile with user-controlled path
const fs = require('fs');
app.get('/file', (req, res) => {
    const filePath = req.query.path;
    fs.readFile(filePath, 'utf8', (err, data) => {
        res.send(data);
    });
});

// Vulnerable: readFileSync with concatenated user input
app.get('/download', (req, res) => {
    fs.readFileSync('./uploads/' + req.params.filename);
});
