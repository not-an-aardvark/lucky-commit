#!/usr/bin/env node
'use strict';
const exec = command => require('child_process').execSync(command).toString();
const desiredString = process.argv[2] || '0000000';
if (!/^[0-9a-f]{1,40}$/.test(desiredString)) {
  throw new TypeError('Invalid input provided. (If an input is provided, it must be a hex string.)');
}
const lastCommit = exec('git cat-file commit head');
const previousDate = exec('git --no-pager show -s --oneline --format="%cd" head');
const previousMessage = exec('git --no-pager show -s --oneline --format="%B" head').slice(0, -2);
let currentStr = lastCommit, counter = 0, whitespace;
do {
  whitespace = (++counter).toString(2).replace(/0/g, ' ').replace(/1/g, '\t');
  const strWithNewMessage = `${lastCommit.slice(0, -1)}${whitespace}\n`;
  currentStr = `commit ${strWithNewMessage.length}\u0000${strWithNewMessage}`;
} while (!require('crypto').createHash('sha1').update(currentStr).digest('hex').startsWith(desiredString))
exec(`GIT_COMMITTER_DATE="${previousDate}" git commit --amend --cleanup=verbatim -m '${previousMessage.replace(/'/g, `'"'"'`)}${whitespace}'`);
