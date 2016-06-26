#!/usr/bin/env node
'use strict';

function exec (command) {
  return require('child_process').execSync(command).toString();
}

const createHash = require('crypto').createHash;
function sha1(str) {
  return createHash('sha1').update(str).digest('hex');
}

function getWhitespaceString(num) {
  return num.toString(2).split('0').join(' ').split('1').join('\t');
}

function luckyCommit (desiredString) {
  desiredString = desiredString.toLowerCase();
  if (!/^[0-9a-f]{1,40}$/.test(desiredString)) {
    throw new TypeError('Invalid input provided. (If an input is provided, it must be a hex string.)');
  }

  const previousDate = exec('git --no-pager show -s --oneline --format="%cd" head').slice(0, -1);

  if (exec('git --no-pager show -s --oneline --format="%GG" head').trim()) {
    exec('GIT_COMMITTER_DATE="' + previousDate + '" git commit --amend --no-gpg-sign --no-edit');
  }

  const lastCommit = exec('git cat-file commit head').slice(0, -1);
  const previousMessage = exec('git --no-pager show -s --oneline --format="%B" head').slice(0, -2);
  let currentString;
  let counter = 0;
  do {
    const strWithNewMessage = lastCommit + getWhitespaceString(++counter) + '\n';
    currentString = 'commit ' + strWithNewMessage.length + '\x00' + strWithNewMessage;
  } while (!sha1(currentString).startsWith(desiredString))
  exec('GIT_COMMITTER_DATE="' + previousDate + '" git commit --amend --cleanup=verbatim --no-gpg-sign -m \'' + previousMessage.replace(/'/g, "'\"'\"'") + getWhitespaceString(counter) + "'");
}

luckyCommit(process.argv[2] || '0000000');
