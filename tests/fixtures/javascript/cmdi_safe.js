const { execSync, execFile } = require('child_process');

const output = execSync('ls -la');

execFile('/usr/bin/git', ['status'], (err, stdout) => {
    console.log(stdout);
});
