#! /usr/bin/env node
'use strict';
const exec = require('child_process').execSync;
const desiredString = process.argv[2] || '0000000';
if (desiredString.length > 40 || !/^[0-9a-f]*$/.test(desiredString)) {
  throw 'Error: Invalid input provided. (If an input is provided, it must be a hex string.)';
}
const lastCommit = exec('git cat-file commit head').toString();
const previousDate = lastCommit.split('\n')[2].match(/\d*? [-|+]\d{4}$/)[0];
let currentStr = lastCommit;
for (let numAttempts = 0; !require('crypto').createHash('sha1').update(currentStr).digest('hex').startsWith(desiredString); numAttempts++) {
  const strWithNewMessage = `${lastCommit.slice(0, -1)}\n\n${numAttempts.toString(36)}\n`;
  currentStr = `commit ${strWithNewMessage.length}\u0000${strWithNewMessage}`;
}
exec(`GIT_COMMITTER_DATE="${previousDate}" git commit --amend -m "${currentStr.split('\n').slice(4, -1).join('\n')}"`);
