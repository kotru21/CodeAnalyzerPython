// Vulnerable: Recursive merge without __proto__ guard
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = target[key] || {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// Vulnerable: Dynamic bracket assignment with user input
app.post('/config', (req, res) => {
    const obj = {};
    obj[req.body.key] = req.body.value;
});
