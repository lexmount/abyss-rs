// Controlled TLS client for the Windows WFP entry-point black-box test.
// Run as a main script with the real Node/Electron executable; never preload it
// into a user's application or bypass certificate verification.
'use strict';

const https = require('node:https');
const fs = require('node:fs');
const { X509Certificate } = require('node:crypto');

const root = new X509Certificate(fs.readFileSync(process.env.ABYSS_ENTRY_TEST_CA));
const request = https.get(process.env.ABYSS_ENTRY_TEST_URL, { agent: false, timeout: 15000 }, response => {
  const socket = response.socket;
  const certificate = new X509Certificate(socket.getPeerCertificate().raw);
  const result = {
    pid: process.pid,
    entry: process.argv[1],
    status: response.statusCode,
    authorized: socket.authorized,
    issuer: certificate.issuer,
    signedByBroker: certificate.verify(root.publicKey),
  };
  response.resume();
  response.on('end', () => {
    // Let TLS and TCP close normally so the broker can record the completed flow.
    process.stdout.write(JSON.stringify(result) + '\n');
  });
});
request.on('timeout', () => request.destroy(new Error('TLS probe timed out')));
request.on('error', error => {
  process.exitCode = 1;
  process.stderr.write(error.message + '\n');
});
