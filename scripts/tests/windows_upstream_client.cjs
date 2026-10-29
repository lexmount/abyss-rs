// Isolated WFP test client. Its executable must be selected by the test adapter rule.
'use strict';

const net = require('node:net');
const tls = require('node:tls');
const fs = require('node:fs');
const input = JSON.parse(process.argv[2]);
const options = { host: input.ip, port: input.port };
if (input.tls) {
  options.servername = input.host;
  if (input.ca) options.ca = fs.readFileSync(input.ca);
}
const stream = input.tls ? tls.connect(options) : net.connect(options);
let output = '';
let first = false;
let certificate = null;
stream.setTimeout(10000, () => stream.destroy(new Error('test connection timed out')));
stream.on(input.tls ? 'secureConnect' : 'connect', () => {
  if (input.tls) certificate = {
    authorized: stream.authorized,
    issuer: stream.getPeerCertificate().issuer,
    fingerprint: stream.getPeerCertificate().fingerprint256,
  };
  stream.write(`GET ${input.path || '/probe'} HTTP/1.1\r\nHost: ${input.host}\r\nAuthorization: Bearer test-only\r\nConnection: close\r\n\r\n`);
});
stream.on('data', data => {
  output += data.toString();
  if (!first && output.includes('data: first\n\n')) {
    first = true;
    process.stdout.write(JSON.stringify({ event: 'first', pid: process.pid }) + '\n');
  }
});
stream.on('error', error => {
  process.stdout.write(JSON.stringify({ event: 'error', error: error.message, pid: process.pid }) + '\n');
  process.exitCode = 1;
});
stream.on('end', () => process.stdout.write(JSON.stringify({
  event: 'end', pid: process.pid, response: output, certificate,
}) + '\n'));
